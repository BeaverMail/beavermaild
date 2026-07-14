package smtp_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/tlsload"
	"github.com/BeaverMail/beaver/internal/tlsload/tlstest"
)

func TestClientSend(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		reply(conn, "220 mx.test ESMTP\r\n")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "EHLO"):
				reply(conn, "250 mx.test\r\n")
			case strings.HasPrefix(line, "MAIL"):
				reply(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "RCPT"):
				reply(conn, "250 OK\r\n")
			case line == "DATA":
				inData = true
				reply(conn, "354 go\r\n")
			default:
				if inData {
					if line == "." {
						inData = false
						reply(conn, "250 queued\r\n")
					}
					continue
				}
				if strings.HasPrefix(line, "QUIT") {
					reply(conn, "221 bye\r\n")
					return
				}
			}
		}
	}()

	ctx := context.Background()
	err = smtp.Send(ctx, ln.Addr().String(), "sender@example.com", "rcpt@example.com", []byte("hello\r\n"), smtp.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	<-done
}

func TestClientSendDotStuff(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var got []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		reply(conn, "220 mx.test ESMTP\r\n")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "EHLO") || strings.HasPrefix(line, "MAIL") || strings.HasPrefix(line, "RCPT"):
				reply(conn, "250 OK\r\n")
			case line == "DATA":
				inData = true
				reply(conn, "354 go\r\n")
			case inData:
				got = append(got, line)
				if line == "." {
					inData = false
					reply(conn, "250 queued\r\n")
				}
			case strings.HasPrefix(line, "QUIT"):
				reply(conn, "221 bye\r\n")
				return
			}
		}
	}()

	ctx := context.Background()
	body := ".starts with dot\r\nnext\r\n"
	err = smtp.Send(ctx, ln.Addr().String(), "sender@example.com", "rcpt@example.com", []byte(body), smtp.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if len(got) < 3 || got[0] != "..starts with dot" || got[1] != "next" || got[2] != "." {
		t.Fatalf("data lines %#v", got)
	}
}

func reply(conn net.Conn, s string) {
	_, _ = fmt.Fprint(conn, s)
}

func TestClientNullSender(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var mailLine string
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		reply(conn, "220 mx.test ESMTP\r\n")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "EHLO"):
				reply(conn, "250-mx.test\r\n250 2.0.0 Ok\r\n")
			case strings.HasPrefix(line, "MAIL"):
				mailLine = line
				reply(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "RCPT"):
				reply(conn, "250 OK\r\n")
			case line == "DATA":
				inData = true
				reply(conn, "354 go\r\n")
			case inData:
				if line == "." {
					inData = false
					reply(conn, "250 queued\r\n")
				}
			case strings.HasPrefix(line, "QUIT"):
				reply(conn, "221 bye\r\n")
				return
			}
		}
	}()

	ctx := context.Background()
	err = smtp.Send(ctx, ln.Addr().String(), "", "rcpt@example.com", []byte("bounce\r\n"), smtp.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if !strings.HasPrefix(mailLine, "MAIL FROM:<>") {
		t.Fatalf("got %q", mailLine)
	}
}

func TestClientRelaySTARTTLSAuth(t *testing.T) {
	t.Parallel()

	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"127.0.0.1"})
	certs, err := tlsload.Load(certFile, keyFile, "1.2")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var authed bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		reply(conn, "220 relay.test ESMTP\r\n")
		if err := readLine(r, "EHLO"); err != nil {
			return
		}
		reply(conn, "250-relay.test\r\n250-STARTTLS\r\n250-AUTH PLAIN\r\n250 OK\r\n")
		if err := readLine(r, "STARTTLS"); err != nil {
			return
		}
		reply(conn, "220 ready\r\n")
		tlsConn := certs.WrapServer(conn)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		defer tlsConn.Close()
		tr := bufio.NewReader(tlsConn)
		if err := readLine(tr, "EHLO"); err != nil {
			return
		}
		reply(tlsConn, "250-relay.test\r\n250-AUTH PLAIN\r\n250 OK\r\n")
		line, err := tr.ReadString('\n')
		if err != nil || !strings.HasPrefix(strings.TrimSpace(line), "AUTH PLAIN") {
			return
		}
		cred, _ := strings.CutPrefix(strings.TrimSpace(line), "AUTH PLAIN ")
		raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
		parts := strings.Split(string(raw), "\x00")
		if len(parts) == 3 && parts[1] == "relayuser" && parts[2] == "relaypass" {
			authed = true
		}
		reply(tlsConn, "235 OK\r\n")
		for _, cmd := range []string{"MAIL", "RCPT", "DATA"} {
			if err := readPrefix(tr, cmd); err != nil {
				return
			}
			if cmd == "DATA" {
				reply(tlsConn, "354 go\r\n")
				for {
					l, err := tr.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(l) == "." {
						break
					}
				}
			}
			reply(tlsConn, "250 OK\r\n")
		}
		reply(tlsConn, "221 bye\r\n")
	}()

	ctx := context.Background()
	err = smtp.Send(ctx, ln.Addr().String(), "sender@example.com", "rcpt@example.com", []byte("relay\r\n"), smtp.ClientOptions{
		STARTTLS:              true,
		TLSInsecureSkipVerify: true,
		User:                  "relayuser",
		Password:              "relaypass",
	})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if !authed {
		t.Fatal("AUTH not verified")
	}
}

func TestClientOpportunisticSTARTTLS(t *testing.T) {
	t.Parallel()

	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"127.0.0.1"})
	certs, err := tlsload.Load(certFile, keyFile, "1.2")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var usedTLS bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		reply(conn, "220 mx.test ESMTP\r\n")
		if err := readLine(r, "EHLO"); err != nil {
			return
		}
		reply(conn, "250-mx.test\r\n250-STARTTLS\r\n250 OK\r\n")
		if err := readLine(r, "STARTTLS"); err != nil {
			return
		}
		usedTLS = true
		reply(conn, "220 ready\r\n")
		tlsConn := certs.WrapServer(conn)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		defer tlsConn.Close()
		tr := bufio.NewReader(tlsConn)
		if err := readLine(tr, "EHLO"); err != nil {
			return
		}
		reply(tlsConn, "250-mx.test\r\n250 OK\r\n")
		runSimpleMail(tr, tlsConn)
	}()

	ctx := context.Background()
	err = smtp.Send(ctx, ln.Addr().String(), "sender@example.com", "rcpt@example.com", []byte("tls\r\n"), smtp.ClientOptions{
		OpportunisticSTARTTLS: true,
		TLSInsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if !usedTLS {
		t.Fatal("expected STARTTLS upgrade")
	}
}

func TestClientSendBDAT(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var bdatLine string
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		reply(conn, "220 mx.test ESMTP\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "EHLO"):
				reply(conn, "250-mx.test\r\n250-CHUNKING\r\n250 OK\r\n")
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				reply(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "BDAT"):
				bdatLine = line
				reply(conn, "250 OK\r\n")
				payload, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if payload != "chunk\r\n" {
					return
				}
				reply(conn, "250 queued\r\n")
				return
			case strings.HasPrefix(line, "QUIT"):
				reply(conn, "221 bye\r\n")
				return
			}
		}
	}()

	ctx := context.Background()
	err = smtp.Send(ctx, ln.Addr().String(), "sender@example.com", "rcpt@example.com", []byte("chunk\r\n"), smtp.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if !strings.HasPrefix(bdatLine, "BDAT 7 LAST") {
		t.Fatalf("got %q", bdatLine)
	}
}

func TestClientSendPipelining(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var batch []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		reply(conn, "220 mx.test ESMTP\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			batch = append(batch, line)
			switch {
			case strings.HasPrefix(line, "EHLO"):
				reply(conn, "250-mx.test\r\n250-PIPELINING\r\n250 OK\r\n")
			case strings.HasPrefix(line, "MAIL"):
				reply(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "RCPT"):
				reply(conn, "250 OK\r\n")
			case line == "DATA":
				reply(conn, "354 go\r\n")
			default:
				if line == "." {
					reply(conn, "250 queued\r\n")
					return
				}
			}
		}
	}()

	ctx := context.Background()
	err = smtp.Send(ctx, ln.Addr().String(), "sender@example.com", "rcpt@example.com", []byte("pipe\r\n"), smtp.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if len(batch) < 4 || batch[1] != "MAIL FROM:<sender@example.com> SIZE=6" || batch[2] != "RCPT TO:<rcpt@example.com>" || batch[3] != "DATA" {
		t.Fatalf("batch %#v", batch)
	}
}

func readLine(r *bufio.Reader, prefix string) error {
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimSpace(line), prefix) {
		return fmt.Errorf("want %s got %q", prefix, line)
	}
	return nil
}

func readPrefix(r *bufio.Reader, prefix string) error {
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimSpace(line), prefix) {
		return fmt.Errorf("want prefix %s got %q", prefix, line)
	}
	return nil
}

func runSimpleMail(r *bufio.Reader, conn net.Conn) {
	inData := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
			reply(conn, "250 OK\r\n")
		case line == "DATA":
			inData = true
			reply(conn, "354 go\r\n")
		default:
			if inData {
				if line == "." {
					reply(conn, "250 queued\r\n")
					return
				}
				continue
			}
		}
	}
}
