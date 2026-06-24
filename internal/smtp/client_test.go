package smtp_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/smtp"
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
