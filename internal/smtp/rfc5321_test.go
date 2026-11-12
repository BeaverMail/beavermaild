package smtp_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
)

// rfcDial starts an inbound server on the dev seed (alice@localhost) and returns a client after the
// greeting, past EHLO when helo is set.
func rfcDial(t *testing.T, helo bool) (net.Conn, *bufio.Reader, *mail.Inbox, *directory.Local) {
	t.Helper()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{Hostname: "mx.example.net"})
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
	if helo {
		send(t, conn, "EHLO client.example")
		readEHLO(t, read, "")
	}
	return conn, read, inbox, dir
}

// rfcSession is rfcDial past EHLO.
func rfcSession(t *testing.T) (net.Conn, *bufio.Reader, *mail.Inbox, *directory.Local) {
	t.Helper()
	return rfcDial(t, true)
}

// RFC 5321 4.1.1.2 / 4.5.5: bounces arrive with the null reverse-path and must be accepted; the
// stored copy keeps it as "Return-Path: <>".
func TestRFC5321NullReversePath(t *testing.T) {
	t.Parallel()
	conn, read, inbox, dir := rfcSession(t)

	send(t, conn, "MAIL FROM:<>")
	expect(t, read, "250 ")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, read, "250 ")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "From: Mail Delivery System <mailer-daemon@example.org>")
	send(t, conn, "Subject: Undelivered Mail Returned to Sender")
	send(t, conn, "")
	send(t, conn, "bounce body")
	send(t, conn, ".")
	expect(t, read, "250 ")

	// The transaction is over: RCPT needs a new MAIL, even though the last sender was null.
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, read, "503 ")

	ctx := context.Background()
	acc, _, err := dir.ResolveEmail(ctx, "alice@localhost")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("inbox %d, %v", len(msgs), err)
	}
	raw, err := inbox.LoadRaw(ctx, msgs[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	if first, _, _ := strings.Cut(string(raw), "\n"); strings.TrimSuffix(first, "\r") != "Return-Path: <>" {
		t.Fatalf("stored message:\n%s", raw)
	}
}

// RFC 5321 4.5.1: postmaster@<served domain> and the bare "Postmaster" are always accepted; with no
// postmaster account or alias they reach the admin (alice is the dev seed admin).
func TestRFC5321Postmaster(t *testing.T) {
	t.Parallel()
	conn, read, inbox, dir := rfcSession(t)

	send(t, conn, "MAIL FROM:<admin@example.org>")
	expect(t, read, "250 ")
	for _, rcpt := range []string{"<Postmaster>", "<postmaster@localhost>", "<PostMaster@LOCALHOST>"} {
		send(t, conn, "RCPT TO:"+rcpt)
		expect(t, read, "250 ")
	}
	send(t, conn, "RCPT TO:<nobody@localhost>")
	expect(t, read, "550 ")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: your server is sending spam")
	send(t, conn, "")
	send(t, conn, "details")
	send(t, conn, ".")
	expect(t, read, "250 ")

	ctx := context.Background()
	acc, _, err := dir.ResolveEmail(ctx, "alice@localhost")
	if err != nil {
		t.Fatal(err)
	}
	// One copy per mailbox, however many postmaster forms were used.
	if msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID); err != nil || len(msgs) != 1 {
		t.Fatalf("admin inbox %d, %v", len(msgs), err)
	}
}

// RFC 5321 2.4: a remote local part is case-sensitive and must be kept as sent (only the domain folds),
// while our own users still match case-insensitively.
func TestRFC5321LocalPartCase(t *testing.T) {
	t.Parallel()
	conn, read, inbox, dir := rfcSession(t)
	send(t, conn, "MAIL FROM:<John.Doe@Example.ORG>")
	expect(t, read, "250 ")
	send(t, conn, "RCPT TO:<ALICE@LocalHost>")
	expect(t, read, "250 ")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: case")
	send(t, conn, "")
	send(t, conn, "body")
	send(t, conn, ".")
	expect(t, read, "250 ")

	ctx := context.Background()
	acc, _, err := dir.ResolveEmail(ctx, "alice@localhost")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("inbox %d, %v", len(msgs), err)
	}
	raw, err := inbox.LoadRaw(ctx, msgs[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	if first, _, _ := strings.Cut(string(raw), "\n"); strings.TrimSuffix(first, "\r") != "Return-Path: <John.Doe@example.org>" {
		t.Fatalf("stored message:\n%s", raw)
	}
}

// Command/reply exchanges straight from RFC 5321: each step is a command and the reply prefix it must get.
func TestRFC5321Exchanges(t *testing.T) {
	t.Parallel()
	type step struct{ cmd, want string }
	for _, tc := range []struct {
		name  string
		helo  bool
		steps []step
	}{
		{"4.1.4 MAIL needs EHLO/HELO first", false, []step{
			{"MAIL FROM:<a@example.org>", "503 "}, {"NOOP", "250 "}, {"HELO client.example", "250 "}, {"MAIL FROM:<a@example.org>", "250 "}}},
		{"4.1.4 EHLO without a domain is 501 and changes nothing", false, []step{
			{"EHLO", "501 "}, {"HELO", "501 "}, {"MAIL FROM:<a@example.org>", "503 "}}},
		{"4.1.4 MAIL inside an open transaction is 503", true, []step{
			{"MAIL FROM:<a@example.org>", "250 "}, {"MAIL FROM:<b@example.org>", "503 "}, {"RCPT TO:<alice@localhost>", "250 "}}},
		{"4.1.4 a new EHLO resets the transaction", true, []step{
			{"MAIL FROM:<a@example.org>", "250 "}, {"EHLO client.example", "250"}}},
		{"4.2.4 unknown command 500, known but unimplemented 502", true, []step{
			{"FOOBAR", "500 "}, {"TURN", "502 "}, {"NOOP", "250 "}}},
		{"4.1.1.11 unknown MAIL/RCPT parameter is 555", true, []step{
			{"MAIL FROM:<a@example.org> FOO=bar", "555 "}, {"MAIL FROM:<a@example.org> FOO", "555 "},
			{"MAIL FROM:<a@example.org>", "250 "}, {"RCPT TO:<alice@localhost> FOO=bar", "555 "}, {"RCPT TO:<alice@localhost>", "250 "}}},
		{"4.1.2 quoted local parts", true, []step{
			{`MAIL FROM:<"john doe"@example.org>`, "250 "}, {`RCPT TO:<"alice"@localhost>`, "250 "}, {`RCPT TO:<"a>b"@localhost>`, "550 "}}},
		{"3.6.1 source routes are ignored", true, []step{
			{"MAIL FROM:<@relay.example:a@example.org>", "250 "},
			{"RCPT TO:<@one.example,@[IPv6:2001:db8::1]:alice@localhost>", "250 "}}},
		{"4.5.3.1.9 an overlong line gets 500 and the session goes on", true, []step{
			{"NOOP " + strings.Repeat("x", 13000), "500 "}, {"NOOP", "250 "}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn, read, _, _ := rfcDial(t, tc.helo)
			for _, st := range tc.steps {
				send(t, conn, st.cmd)
				if strings.HasPrefix(st.cmd, "EHLO ") {
					readEHLO(t, read, "")
					// After the EHLO the old transaction is gone.
					send(t, conn, "RCPT TO:<alice@localhost>")
					expect(t, read, "503 ")
					continue
				}
				expect(t, read, st.want)
			}
		})
	}
}
