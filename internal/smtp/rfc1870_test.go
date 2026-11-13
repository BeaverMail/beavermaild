package smtp_test

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/smtp"
)

// RFC 1870: the message size counts CRLF (5), so a message over the announced limit is refused
// with 552 even though it is stored with LF; one SIZE per MAIL (6); size-value is up to 20 digits,
// and a valid one past what fits in an int is simply too big.
func TestRFC1870ServerLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{DataLimits: smtp.DataLimits{MaxMessageBytes: 1000}})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeListener(sctx, ln) }()
	time.Sleep(20 * time.Millisecond)
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO test")
	readEHLO(t, read, "SIZE 1000")

	for _, st := range []struct{ send, want string }{
		{"MAIL FROM:<x@example.org> SIZE=10 SIZE=20", "501"},
		{"MAIL FROM:<x@example.org> SIZE=99999999999999999999", "552"},
		{"MAIL FROM:<x@example.org> SIZE=123456789012345678901", "501"}, // 21 digits
	} {
		send(t, conn, st.send)
		expect(t, read, st.want)
	}
	deliver := func(lines int) string {
		send(t, conn, "MAIL FROM:<x@example.org>")
		expect(t, read, "250")
		send(t, conn, "RCPT TO:<alice@localhost>")
		expect(t, read, "250")
		send(t, conn, "DATA")
		expect(t, read, "354")
		// 29 octets of header, then 3 per line with CRLF (2 as stored with LF).
		send(t, conn, "Subject: many-short-lines\r\n\r\n"+strings.Repeat("x\r\n", lines)+".")
		l, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	if got := deliver(400); !strings.HasPrefix(got, "552") { // 1229 octets: 829 as stored
		t.Fatalf("message over SIZE 1000 counted with CRLF: %q", got)
	}
	if got := deliver(320); !strings.HasPrefix(got, "250") { // 989 octets
		t.Fatalf("message under the limit: %q", got)
	}
}

// RFC 1870 7: a message over the SIZE the server announced is failed at once, permanently,
// without being transferred (not even MAIL is sent).
func TestRFC1870ClientChecksAnnouncedLimit(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	sawMail := make(chan bool, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		_, _ = c.Write([]byte("220 mx.test\r\n"))
		mail := false
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				sawMail <- mail
				return
			}
			switch up := strings.ToUpper(l); {
			case strings.HasPrefix(up, "EHLO"):
				_, _ = c.Write([]byte("250-mx.test\r\n250 SIZE 100\r\n"))
			case strings.HasPrefix(up, "MAIL"):
				mail = true
				_, _ = c.Write([]byte("250 ok\r\n"))
			default:
				_, _ = c.Write([]byte("221 bye\r\n"))
			}
		}
	}()
	err = smtp.Send(context.Background(), ln.Addr().String(), "a@example.org", "b@example.net", []byte(strings.Repeat("x", 200)), smtp.ClientOptions{})
	var de *smtp.DeliveryError
	if !errors.As(err, &de) || !de.Permanent {
		t.Fatalf("want a permanent failure, got %v", err)
	}
	if <-sawMail {
		t.Fatal("MAIL sent for a message over the announced SIZE")
	}
}
