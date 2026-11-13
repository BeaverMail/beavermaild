package smtp_test

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
	"github.com/BeaverMail/beavermaild/internal/tlsload/tlstest"
)

// submissionSession starts an implicit-TLS submission server with a queue and returns a session
// authenticated as the seeded alice@localhost.
func submissionSession(t *testing.T) (net.Conn, *bufio.Reader) {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	if _, err := directory.SeedDev(ctx, dir); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"localhost"})
	certs, err := tlsload.Load(certFile, keyFile, "1.2")
	if err != nil {
		t.Fatal(err)
	}
	blobs := blob.NewFS(t.TempDir() + "/blobs")
	tlsLn, err := certs.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, mail.NewInbox(store, blobs), mail.NewQueue(store, blobs), "", "", smtp.Options{Certs: certs})
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = srv.ServeSubmissionListener(sctx, tlsLn, true) }()
	conn, err := tlsload.DialTestClient(tlsLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO test")
	readEHLO(t, read, "AUTH PLAIN")
	send(t, conn, "AUTH PLAIN "+plainCred("alice@localhost", directory.SeedPassword()))
	expect(t, read, "235")
	return conn, read
}

// RFC 6409 4.2 (MUST), 5.1: recipient domains of a submission are well formed and fully qualified.
// Before: queued, then bounced at delivery.
func TestRFC6409RecipientDomains(t *testing.T) {
	t.Parallel()
	conn, read := submissionSession(t)
	send(t, conn, "MAIL FROM:<alice@localhost>")
	expect(t, read, "250")
	for _, st := range []struct{ rcpt, want string }{
		{"bob@example.org", "250"},
		{"alice@localhost", "250"}, // hosted single-label domain: ours, accepted
		{"bob@sales", "554 5.1.2"},
		{"bob@foo..example", "501 5.1.3"},
		{"bob@-foo.example", "501 5.1.3"},
		{"bob@foo_bar.example", "501 5.1.3"},
		{"bob@example.org.", "501 5.1.3"},
	} {
		send(t, conn, "RCPT TO:<"+st.rcpt+">")
		expect(t, read, st.want)
	}
}

// RFC 6409 8 (MUST): a submission that is not valid RFC 5322 is refused after the data, with the reason.
func TestRFC6409RejectsNonConformingMessage(t *testing.T) {
	t.Parallel()
	conn, read := submissionSession(t)
	submit := func(header, want string) {
		t.Helper()
		send(t, conn, "MAIL FROM:<alice@localhost>")
		expect(t, read, "250")
		send(t, conn, "RCPT TO:<bob@example.org>")
		expect(t, read, "250")
		send(t, conn, "DATA")
		expect(t, read, "354")
		send(t, conn, header)
		send(t, conn, "")
		send(t, conn, "body")
		send(t, conn, ".")
		expect(t, read, want)
	}
	submit("Subject: no from", "554 5.6.0")
	submit("From: <alice@localhost>\r\nTo: <bob@sales>", "554 5.6.0")
	submit("From: <alice@localhost>\r\nTo: <bob@example.org>", "250")
}
