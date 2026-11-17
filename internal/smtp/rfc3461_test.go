package smtp_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/mailauth"
	"github.com/BeaverMail/beavermaild/internal/smtp"
)

// RFC 3461 4: ENVID and ORCPT are xtext decoding to printable ASCII (ENVID up to 100 characters),
// RET/ENVID/NOTIFY/ORCPT appear at most once, NOTIFY has a value. Anything else gets 501.
func TestRFC3461Parameters(t *testing.T) {
	t.Parallel()
	conn, read, _, _ := rfcDial(t, true)
	for _, st := range []struct{ send, want string }{
		{"MAIL FROM:<x@example.org> RET=FULL RET=HDRS", "501"},
		{"MAIL FROM:<x@example.org> ENVID=a ENVID=b", "501"},
		{"MAIL FROM:<x@example.org> ENVID=" + strings.Repeat("A", 101), "501"},
		{"MAIL FROM:<x@example.org> ENVID=env+0D+0AInjected:+20x", "501"},
		{"MAIL FROM:<x@example.org> ENVID=bad+zz", "501"},
		{"MAIL FROM:<x@example.org> RET=HDRS ENVID=" + strings.Repeat("A", 100), "250"},
		{"RCPT TO:<alice@localhost> NOTIFY=SUCCESS NOTIFY=NEVER", "501"},
		{"RCPT TO:<alice@localhost> NOTIFY=", "501"},
		{"RCPT TO:<alice@localhost> ORCPT=rfc822;a+0D+0AX:+20y", "501"},
		{"RCPT TO:<alice@localhost> ORCPT=no-type-separator", "501"},
		{"RCPT TO:<alice@localhost> ORCPT=rfc822;a@example.org ORCPT=rfc822;b@example.org", "501"},
		{"RCPT TO:<alice@localhost> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;alice+40localhost", "250"},
	} {
		send(t, conn, st.send)
		expect(t, read, st.want)
	}
}

// RFC 3461 5.2.3 (a): a local delivery with NOTIFY=SUCCESS gets a "delivered" DSN, sent with the
// server's name and the ENVID and ORCPT decoded (6.3). RFC 3461 8, RFC 6533 7: only when the return
// path's SPF passes, or a forged one would get the message's header fields.
func TestRFC3461LocalSuccessDSN(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		policy string
		dsn    bool
	}{{"v=spf1 +all", true}, {"v=spf1 -all", false}} {
		conn, read, inbox, dir := spfDial(t, tc.policy)
		for _, st := range []struct{ send, want string }{
			{"MAIL FROM:<bob@example.org> ENVID=job+2D42", "250"},
			{"RCPT TO:<alice@localhost> NOTIFY=SUCCESS ORCPT=rfc822;Alice+40localhost", "250"},
			{"DATA", "354"},
			{"From: sender@example.com\r\nSubject: hi\r\n\r\nbody\r\n.", "250"},
		} {
			send(t, conn, st.send)
			expect(t, read, st.want)
		}
		ctx := context.Background()
		acc, _, err := dir.ResolveEmail(ctx, "bob@example.org")
		if err != nil {
			t.Fatal(err)
		}
		msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
		if want := map[bool]int{true: 1, false: 0}[tc.dsn]; err != nil || len(msgs) != want {
			t.Fatalf("%s: want %d DSN, got %d (%v)", tc.policy, want, len(msgs), err)
		}
		if !tc.dsn {
			continue
		}
		var dsn string
		for _, m := range msgs {
			raw, _ := inbox.LoadMessage(ctx, m.Meta)
			if strings.Contains(string(raw), "multipart/report") {
				dsn = string(raw)
			}
		}
		for _, want := range []string{"Action: delivered", "Reporting-MTA: dns; mx.example.net", "Original-Envelope-Id: job-42",
			"Original-Recipient: rfc822;Alice@localhost", "MAILER-DAEMON@mx.example.net"} {
			if !strings.Contains(dsn, want) {
				t.Fatalf("DSN lacks %q:\n%s", want, dsn)
			}
		}
	}
}

// spfDial is rfcDial with SPF on, every domain publishing policy, and bob@example.org hosted.
func spfDial(t *testing.T, policy string) (net.Conn, *bufio.Reader, *mail.Inbox, *directory.Local) {
	t.Helper()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)
	// The return path: a hosted FQDN (SPF gives "none" for a single label such as localhost).
	dom, err := dir.CreateDomain(ctx, directory.DefaultTenantID, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAccount(ctx, dom.ID, "bob", "secret-pass-1"); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{
		Hostname: "mx.example.net",
		MailAuth: mailauth.New(mailauth.Config{Enabled: true, SPFEnabled: true, SPFResolver: fixedSPF(policy)}),
	})
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = srv.ServeListener(sctx, ln) }()
	time.Sleep(20 * time.Millisecond)
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO client.example")
	readEHLO(t, read, "")
	return conn, read, inbox, dir
}

// fixedSPF answers every TXT query with the same SPF policy.
type fixedSPF string

func (p fixedSPF) Resolve(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeTXT {
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{string(p)},
		})
	}
	return resp, nil
}

// fakeMX answers one transaction, offering DSN or not, and reports the MAIL and RCPT lines.
func fakeMX(t *testing.T, dsn bool) (string, <-chan [2]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	lines := make(chan [2]string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		w := func(s string) { _, _ = c.Write([]byte(s)) }
		w("220 mx.test\r\n")
		var mailLine, rcptLine string
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimSpace(l)
			switch up := strings.ToUpper(l); {
			case strings.HasPrefix(up, "EHLO"):
				if dsn {
					w("250-mx.test\r\n250 DSN\r\n")
				} else {
					w("250 mx.test\r\n")
				}
			case strings.HasPrefix(up, "MAIL"):
				mailLine = l
				w("250 ok\r\n")
			case strings.HasPrefix(up, "RCPT"):
				rcptLine = l
				w("250 ok\r\n")
			case up == "DATA":
				w("354 go\r\n")
				for {
					d, err := r.ReadString('\n')
					if err != nil || strings.TrimSpace(d) == "." {
						break
					}
				}
				w("250 queued\r\n")
				lines <- [2]string{mailLine, rcptLine}
			case up == "QUIT":
				w("221 bye\r\n")
				return
			default:
				w("250 ok\r\n")
			}
		}
	}()
	return ln.Addr().String(), lines
}

// RFC 3461 5.2.1/5.2.2 (a): relaying to a server with DSN passes the received parameters
// unchanged, and only those; to one without DSN, none.
func TestRFC3461RelayParameters(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, offered := range []bool{true, false} {
		addr, lines := fakeMX(t, offered)
		d := &mail.RelayDSN{Ret: mail.RetHdrs, Envid: "job+2D42", Notify: mail.NotifyToStorage(mail.NotifySuccess | mail.NotifyFailure), Orcpt: "rfc822;Alice+40example.org"}
		if err := smtp.Send(ctx, addr, "a@example.org", "b@example.net", []byte("Subject: s\r\n\r\nx\r\n"), smtp.ClientOptions{DSN: d}); err != nil {
			t.Fatal(err)
		}
		got := <-lines
		withParams := strings.Contains(got[0], " RET=HDRS ENVID=job+2D42") && strings.Contains(got[1], " NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;Alice+40example.org")
		if withParams != offered || d.Passed != offered {
			t.Fatalf("DSN offered %v: MAIL %q RCPT %q passed %v", offered, got[0], got[1], d.Passed)
		}
	}
	// The same RelayDSN tried on a DSN server, then delivered by one without: not passed (MX fallback).
	d := &mail.RelayDSN{Notify: mail.NotifyToStorage(mail.NotifySuccess)}
	for _, offered := range []bool{true, false} {
		addr, lines := fakeMX(t, offered)
		if err := smtp.Send(ctx, addr, "a@example.org", "b@example.net", []byte("x\r\n"), smtp.ClientOptions{DSN: d}); err != nil {
			t.Fatal(err)
		}
		<-lines
	}
	if d.Passed {
		t.Fatal("Passed left over from an earlier server")
	}
	// Parameters not received are not added (5.2.1 (c)): no NOTIFY, no RET, no ENVID.
	addr, lines := fakeMX(t, true)
	if err := smtp.Send(ctx, addr, "a@example.org", "b@example.net", []byte("x\r\n"), smtp.ClientOptions{DSN: &mail.RelayDSN{}}); err != nil {
		t.Fatal(err)
	}
	if got := <-lines; strings.Contains(got[0]+got[1], "RET=") || strings.Contains(got[0]+got[1], "ENVID=") ||
		strings.Contains(got[0]+got[1], "NOTIFY=") || strings.Contains(got[0]+got[1], "ORCPT=") {
		t.Fatalf("parameters invented: %q %q", got[0], got[1])
	}
}
