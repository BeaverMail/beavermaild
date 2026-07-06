package smtp_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

type phaseFilter struct {
	phase  string
	action string
}

func (f phaseFilter) Filter(_ context.Context, req smtp.FilterRequest) (smtp.FilterOutcome, error) {
	if req.Phase == f.phase {
		if f.action == "" {
			return smtp.FilterOutcome{Action: smtp.FilterActionReject}, nil
		}
		return smtp.FilterOutcome{Action: f.action}, nil
	}
	return smtp.FilterOutcome{Action: smtp.FilterActionAccept}, nil
}

func TestSMTPFilterRejectAtEom(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, inbox, dir := openSMTPTestStore(t, ctx)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{
		Filter:       phaseFilter{phase: smtp.FilterPhaseEom},
		FilterTmpDir: tmpDir,
	})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeListener(sctx, ln) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "HELO test")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: hi")
	send(t, conn, "")
	send(t, conn, "body")
	send(t, conn, ".")
	expectPrefix(t, read, "550")

	key := storage.AppendKey(nil, storage.SubspaceMail, 1, 1, byte(storage.CollectionEmail), nil)
	if _, err := store.Get(ctx, key); err == nil {
		t.Fatal("message should not be stored")
	}
}

func TestSMTPFilterAcceptDelivers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, inbox, dir := openSMTPTestStore(t, ctx)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{
		Filter:       phaseFilter{phase: smtp.FilterPhaseEom, action: smtp.FilterActionAccept},
		FilterTmpDir: t.TempDir(),
	})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeListener(sctx, ln) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "HELO test")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: hi")
	send(t, conn, "")
	send(t, conn, "hello inbox")
	send(t, conn, ".")
	expect(t, read, "250")

	key := storage.AppendKey(nil, storage.SubspaceMail, 1, 1, byte(storage.CollectionEmail), nil)
	if _, err := store.Get(ctx, key); err != nil {
		t.Fatalf("email not stored: %v", err)
	}
}

func TestSMTPFilterRejectAtMail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{
		Filter: phaseFilter{phase: smtp.FilterPhaseMail},
	})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeListener(sctx, ln) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "HELO test")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expectPrefix(t, read, "550")
}

func openSMTPTestStore(t *testing.T, ctx context.Context) (storage.Store, *mail.Inbox, *directory.Local) {
	t.Helper()
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
	inbox := mail.NewInbox(store, blobs)
	return store, inbox, dir
}

func expectPrefix(t *testing.T, r *bufio.Reader, prefix string) {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(line), prefix) {
		t.Fatalf("expected prefix %q got %q", prefix, strings.TrimSpace(line))
	}
}
