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
				reply(conn, "354 go\r\n")
			case line == ".":
				reply(conn, "250 queued\r\n")
			case strings.HasPrefix(line, "QUIT"):
				reply(conn, "221 bye\r\n")
				return
			}
		}
	}()

	ctx := context.Background()
	err = smtp.Send(ctx, ln.Addr().String(), "sender@example.com", "rcpt@example.com", []byte("hello\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	<-done
}

func reply(conn net.Conn, s string) {
	_, _ = fmt.Fprint(conn, s)
}
