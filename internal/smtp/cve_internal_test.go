package smtp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// captureMX accepts one session and returns the raw message bytes the client sent after DATA (or in
// BDAT chunks when chunking is advertised), terminator included.
func captureMX(t *testing.T, chunking bool) (addr string, got <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		_, _ = io.WriteString(conn, "220 mx.example.net ESMTP\r\n")
		var body []byte
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				ch <- body
				return
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"):
				if chunking {
					_, _ = io.WriteString(conn, "250-mx.example.net\r\n250 CHUNKING\r\n")
				} else {
					_, _ = io.WriteString(conn, "250 mx.example.net\r\n")
				}
			case cmd == "DATA":
				_, _ = io.WriteString(conn, "354 go\r\n")
				for !bytes.HasSuffix(body, []byte("\r\n.\r\n")) {
					b, err := r.ReadByte()
					if err != nil {
						ch <- body
						return
					}
					body = append(body, b)
				}
				_, _ = io.WriteString(conn, "250 queued\r\n")
			case strings.HasPrefix(cmd, "BDAT"):
				var n int
				_, _ = fmtSscan(cmd, &n)
				chunk := make([]byte, n)
				if _, err := io.ReadFull(r, chunk); err != nil {
					ch <- body
					return
				}
				body = append(body, chunk...)
				_, _ = io.WriteString(conn, "250 ok\r\n")
			case cmd == "QUIT":
				_, _ = io.WriteString(conn, "221 bye\r\n")
				ch <- body
				return
			default:
				_, _ = io.WriteString(conn, "250 ok\r\n")
			}
		}
	}()
	return ln.Addr().String(), ch
}

func fmtSscan(cmd string, n *int) (int, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	v := 0
	for _, c := range f[1] {
		v = v*10 + int(c-'0')
	}
	*n = v
	return 1, nil
}

// SMTP smuggling, outbound side (CVE-2023-51764 class): whatever bare CR/LF a stored message holds,
// what we send must have only CRLF line ends (RFC 5321 2.3.8: a client MUST NOT send bare CR or LF)
// and a single end-of-data, so no receiver can be made to see an early end.
func TestCVE_2023_51764_SMTPSmugglingOutbound(t *testing.T) {
	t.Parallel()
	const smuggled = "MAIL FROM:<ceo@victim.example>\r\nRCPT TO:<bob@example.org>\r\nDATA\r\nforged\r\n"
	for _, chunking := range []bool{false, true} {
		for _, end := range []string{"\n.\n", "\n.\r\n", "\r.\r\n", "\r\n.\r", "\r.\n", "\r\n.\n", "\n.\r", "\r.\r"} {
			addr, got := captureMX(t, chunking)
			msg := "Subject: hi\r\n\r\nbody" + end + smuggled
			if _, err := SendReply(context.Background(), addr, "alice@example.net", "bob@example.org", []byte(msg), ClientOptions{}); err != nil {
				t.Fatalf("chunking=%v %q: %v", chunking, end, err)
			}
			wire := <-got
			for i, c := range wire {
				if c == '\r' && (i+1 == len(wire) || wire[i+1] != '\n') || c == '\n' && (i == 0 || wire[i-1] != '\r') {
					t.Fatalf("chunking=%v %q: bare CR/LF at %d in %q", chunking, end, i, wire)
				}
			}
			if !chunking {
				if i := bytes.Index(wire, []byte("\r\n.\r\n")); i != len(wire)-5 {
					t.Fatalf("%q: end-of-data at %d of %d in %q", end, i, len(wire), wire)
				}
			}
		}
	}
}

// plainRelay is a relay without STARTTLS that accepts AUTH; it records every command line.
func plainRelay(t *testing.T) (addr string, cmds func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []string, 1)
	go func() {
		var seen []string
		defer func() { got <- seen }()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		_, _ = io.WriteString(conn, "220 relay.example.net ESMTP\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.TrimSpace(line)
			seen = append(seen, cmd)
			switch up := strings.ToUpper(cmd); {
			case strings.HasPrefix(up, "EHLO"):
				_, _ = io.WriteString(conn, "250-relay.example.net\r\n250 AUTH PLAIN\r\n")
			case strings.HasPrefix(up, "AUTH"):
				_, _ = io.WriteString(conn, "235 ok\r\n")
			case up == "DATA":
				_, _ = io.WriteString(conn, "354 go\r\n")
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
				}
				_, _ = io.WriteString(conn, "250 queued\r\n")
			case up == "QUIT":
				_, _ = io.WriteString(conn, "221 bye\r\n")
				return
			default:
				_, _ = io.WriteString(conn, "250 ok\r\n")
			}
		}
	}()
	return ln.Addr().String(), func() []string { return <-got }
}

// STARTTLS stripping on the relay hop (the CVE-2011-0411 era downgrades, RFC 4954 14): relay
// credentials never go out in clear, and a relay configured for STARTTLS that does not offer it is a
// failure, not a silent fallback. Only a loopback relay may take AUTH without TLS.
func TestRelayCredentialsNeverInClear(t *testing.T) {
	t.Parallel()
	creds := ClientOptions{User: "relayuser", Password: "s3cret"}
	for _, tc := range []struct {
		name    string
		opts    ClientOptions
		wantErr error
	}{
		{"STARTTLS configured, not offered", ClientOptions{STARTTLS: true, User: creds.User, Password: creds.Password}, errStartTLSMissing},
		{"no TLS at all", creds, errPlainAuth},
		{"loopback relay allowed", ClientOptions{User: creds.User, Password: creds.Password, AllowPlainAuth: true}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr, cmds := plainRelay(t)
			_, err := SendReply(context.Background(), addr, "a@example.net", "b@example.org", []byte("Subject: x\r\n\r\nhi\r\n"), tc.opts)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err %v, want %v", err, tc.wantErr)
			}
			sentAuth := false
			for _, c := range cmds() {
				sentAuth = sentAuth || strings.HasPrefix(strings.ToUpper(c), "AUTH")
			}
			if sentAuth != (tc.wantErr == nil) {
				t.Fatalf("AUTH sent: %v", sentAuth)
			}
		})
	}
	for addr, want := range map[string]bool{"127.0.0.1:25": true, "[::1]:587": true, "localhost:25": true, "LOCALHOST": true,
		"192.0.2.10:587": false, "relay.example.net:587": false, "10.0.0.5:25": false} {
		if IsLoopbackAddr(addr) != want {
			t.Errorf("IsLoopbackAddr(%q) = %v", addr, !want)
		}
	}
}

// SSRF through DNS: a remote domain whose MX (or implicit MX) points at loopback or a private network
// must not make us connect there. The check runs at connect time, after resolution.
func TestMXDeliveryRefusesPrivateAddresses(t *testing.T) {
	t.Parallel()
	mx := startMockMX(t, mxScript{})
	t.Cleanup(mx.close)
	_, err := deliverMX(context.Background(), []string{mx.addr}, "a@example.net", "b@example.org", []byte("hi\r\n"), ClientOptions{RejectPrivate: true})
	if !errors.Is(err, errPrivateAddr) || !deliveryPermanent(err) {
		t.Fatalf("err %v, want permanent errPrivateAddr", err)
	}
	if mx.accepted() {
		t.Fatal("connected to the loopback MX")
	}
	for _, a := range []string{"127.0.0.1:25", "10.1.2.3:25", "172.16.0.1:25", "192.168.1.1:25", "169.254.1.1:25", "[::1]:25", "[fd00::1]:25", "[fe80::1]:25", "0.0.0.0:25"} {
		if err := rejectPrivateAddr("tcp", a, nil); !errors.Is(err, errPrivateAddr) {
			t.Errorf("%s allowed", a)
		}
	}
	for _, a := range []string{"192.0.2.10:25", "[2001:db8::1]:25"} {
		if err := rejectPrivateAddr("tcp", a, nil); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
}
