package smtp_test

import (
	"bufio"
	"context"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/security"
	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
	"github.com/BeaverMail/beaver/internal/tlsload"
	"github.com/BeaverMail/beaver/internal/tlsload/tlstest"
)

func TestSMTPSubmissionAuthRateLimit(t *testing.T) {
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
	gate := security.NewRateLimitGate(security.RateLimitConfig{MaxAttempts: 2, Window: time.Minute})

	tlsLn, err := certs.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, inbox, nil, "", "", smtp.Options{Certs: certs, AuthGate: gate})
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

	bad := plainCred("alice@localhost", "wrong")
	for i := 0; i < 2; i++ {
		send(t, conn, "AUTH PLAIN "+bad)
		expect(t, read, "535")
	}
	send(t, conn, "AUTH PLAIN "+bad)
	expect(t, read, "454")
}
