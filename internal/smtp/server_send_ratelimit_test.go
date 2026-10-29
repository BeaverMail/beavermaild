package smtp_test

import (
	"bufio"
	"context"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/security"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
	"github.com/BeaverMail/beavermaild/internal/tlsload/tlstest"
)

func TestSMTPSubmissionSendRateLimit(t *testing.T) {
	t.Parallel()

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
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)
	sendGate := security.NewSendLimitGate(security.SendLimitConfig{MaxMessages: 1, Window: time.Hour})

	tlsLn, err := certs.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, inbox, queue, "", "", smtp.Options{
		Certs:    certs,
		SendGate: sendGate,
	})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeSubmissionListener(sctx, tlsLn, true) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := tlsload.DialTestClient(tlsLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO test")
	readEHLO(t, read, "AUTH PLAIN")
	send(t, conn, "AUTH PLAIN "+plainCred("alice@localhost", directory.SeedPassword()))
	expect(t, read, "235")

	submitOne := func(wantPrefix string) {
		t.Helper()
		send(t, conn, "MAIL FROM:<alice@localhost>")
		expect(t, read, "250")
		send(t, conn, "RCPT TO:<bob@example.com>")
		expect(t, read, "250")
		send(t, conn, "DATA")
		expect(t, read, "354")
		send(t, conn, "Subject: rate")
		send(t, conn, "")
		send(t, conn, "body")
		send(t, conn, ".")
		expect(t, read, wantPrefix)
	}

	submitOne("250")
	submitOne("452")
}
