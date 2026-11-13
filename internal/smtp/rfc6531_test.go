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
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
)

// ehloMX accepts one session, answering EHLO with ehlo, and returns the commands it received.
func ehloMX(t *testing.T, ehlo string) (string, <-chan []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		w := func(s string) { _, _ = c.Write([]byte(s)) }
		w("220 mx.test\r\n")
		var cmds []string
		defer func() { out <- cmds }()
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimRight(l, "\r\n")
			cmds = append(cmds, l)
			switch up := strings.ToUpper(l); {
			case strings.HasPrefix(up, "EHLO"):
				w(ehlo)
			case up == "DATA":
				w("354 go\r\n")
				for {
					d, err := r.ReadString('\n')
					if err != nil || d == ".\r\n" {
						break
					}
				}
				w("250 queued\r\n")
			case up == "QUIT":
				w("221 bye\r\n")
				return
			default:
				w("250 ok\r\n")
			}
		}
	}()
	return ln.Addr().String(), out
}

func cmdWith(cmds []string, prefix string) string {
	for _, c := range cmds {
		if strings.HasPrefix(c, prefix) {
			return c
		}
	}
	return ""
}

// RFC 6531 3.2, 3.4: SMTPUTF8 in MAIL when the envelope or header fields need it, and only then;
// a domain-only U-label goes as A-labels without it; to a server without SMTPUTF8 a message that
// needs it fails for good (5.6.7) before MAIL.
func TestRFC6531Client(t *testing.T) {
	t.Parallel()
	const utf8EHLO = "250-mx.test\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n"
	const asciiEHLO = "250-mx.test\r\n250 8BITMIME\r\n"
	plain := []byte("Subject: s\r\n\r\nbody\r\n")
	utf8Hdr := []byte("Subject: caf\xc3\xa9\r\n\r\nbody\r\n")

	for _, tc := range []struct {
		name, ehlo, from, to string
		data                 []byte
		wantMail, wantRcpt   string // "" = no MAIL sent (permanent 5.6.7)
	}{
		{"utf8 local part", utf8EHLO, "δοκιμή@example.org", "b@example.net", plain, "MAIL FROM:<δοκιμή@example.org> BODY=8BITMIME SMTPUTF8", "RCPT TO:<b@example.net>"},
		{"utf8 header", utf8EHLO, "a@example.org", "b@example.net", utf8Hdr, "MAIL FROM:<a@example.org> BODY=8BITMIME SMTPUTF8", "RCPT TO:<b@example.net>"},
		{"ascii only", utf8EHLO, "a@example.org", "b@example.net", plain, "MAIL FROM:<a@example.org> BODY=8BITMIME", "RCPT TO:<b@example.net>"},
		{"u-label domain", asciiEHLO, "a@bücher.example", "b@münchen.example", plain, "MAIL FROM:<a@xn--bcher-kva.example> BODY=8BITMIME", "RCPT TO:<b@xn--mnchen-3ya.example>"},
		{"utf8 local part, no SMTPUTF8", asciiEHLO, "a@example.org", "δοκιμή@example.net", plain, "", ""},
		{"utf8 header, no SMTPUTF8", asciiEHLO, "a@example.org", "b@example.net", utf8Hdr, "", ""},
	} {
		addr, got := ehloMX(t, tc.ehlo)
		err := smtp.Send(context.Background(), addr, tc.from, tc.to, tc.data, smtp.ClientOptions{})
		cmds := <-got
		if tc.wantMail == "" {
			var de *smtp.DeliveryError
			if !errors.As(err, &de) || !de.Permanent || !errors.Is(err, mail.ErrNeedsSMTPUTF8) || mail.SMTPStatusFromError(err) != "5.6.7" {
				t.Errorf("%s: want a permanent 5.6.7 failure, got %v", tc.name, err)
			}
			if m := cmdWith(cmds, "MAIL"); m != "" {
				t.Errorf("%s: MAIL sent: %q", tc.name, m)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if m := cmdWith(cmds, "MAIL"); m != tc.wantMail {
			t.Errorf("%s: %q, want %q", tc.name, m, tc.wantMail)
		}
		if r := cmdWith(cmds, "RCPT"); r != tc.wantRcpt {
			t.Errorf("%s: %q, want %q", tc.name, r, tc.wantRcpt)
		}
	}
}

// RFC 6531 3.3, 3.5 and RFC 6533 3 on the server: 550 for a UTF-8 MAIL without SMTPUTF8, a "utf-8"
// ORCPT accepted in UTF-8 only in an SMTPUTF8 transaction, a control character escape refused.
func TestRFC6531Server(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{})
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
	readEHLO(t, read, "SMTPUTF8")
	for _, st := range []struct{ send, want string }{
		{"MAIL FROM:<δοκιμή@example.org>", "550 5.6.7"},
		{"MAIL FROM:<x@example.org>", "250"},
		{"RCPT TO:<alice@localhost> ORCPT=utf-8;alïce@localhost", "501"},
		{`RCPT TO:<alice@localhost> ORCPT=utf-8;al\x{EF}ce@localhost`, "250"},
		{"RSET", "250"},
		{"MAIL FROM:<x@example.org> SMTPUTF8", "250"},
		{"RCPT TO:<alice@localhost> ORCPT=utf-8;alïce@localhost", "250"},
		{`RCPT TO:<alice@localhost> ORCPT=utf-8;a\x{0A}b@localhost`, "501"},
	} {
		send(t, conn, st.send)
		expect(t, read, st.want)
	}
}
