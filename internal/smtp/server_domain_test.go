package smtp_test

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestSMTPRCPTUnknownDomainRejectedWithoutQueue(t *testing.T) {
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

	conn := dialSMTP(t, dir, store, nil)
	defer conn.Close()
	read := bufio.NewReader(conn)

	expect(t, read, "220")
	send(t, conn, "HELO test")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<nobody@unknown.test>")
	expect(t, read, "554")
}

func TestSMTPInboundRelayDenied(t *testing.T) {
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

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	queue := mail.NewQueue(store, blobs)
	conn := dialSMTP(t, dir, store, queue)
	defer conn.Close()
	read := bufio.NewReader(conn)

	expect(t, read, "220")
	send(t, conn, "HELO test")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<info@blueboxsoft.com>")
	expect(t, read, "554")

	pending, err := queue.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("inbound relay should not enqueue, got %+v", pending)
	}
}

func TestSMTPRCPTUnknownUser(t *testing.T) {
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
	if _, _, err := dir.EnsureDomain(ctx, directory.DefaultTenantID, "known.test"); err != nil {
		t.Fatal(err)
	}

	conn := dialSMTP(t, dir, store, nil)
	defer conn.Close()
	read := bufio.NewReader(conn)

	expect(t, read, "220")
	send(t, conn, "HELO test")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<nobody@known.test>")
	expect(t, read, "550 5.1.1")
}

func dialSMTP(t *testing.T, dir *directory.Local, store *sqlite.Store, queue *mail.Queue) net.Conn {
	t.Helper()
	ctx := context.Background()
	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, queue, "", "", smtp.Options{})
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = srv.ServeListener(sctx, ln) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
