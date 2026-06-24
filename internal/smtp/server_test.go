package smtp_test

import (
	"bufio"
	"context"
	"fmt"
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

func TestSMTPDeliverMessage(t *testing.T) {
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
	inbox := mail.NewInbox(store, blobs)

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
	send(t, conn, "QUIT")

	key := storage.AppendKey(nil, storage.SubspaceMail, 1, 1, byte(storage.CollectionEmail), nil)
	if _, err := store.Get(ctx, key); err != nil {
		t.Fatalf("email not stored: %v", err)
	}
}

func send(t *testing.T, conn net.Conn, line string) {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil {
		t.Fatal(err)
	}
}

func expect(t *testing.T, r *bufio.Reader, prefix string) {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if len(line) < len(prefix) || line[:len(prefix)] != prefix {
		t.Fatalf("line %q want prefix %q", line, prefix)
	}
}

// readEHLO consumes EHLO continuation lines; mustContain must appear when non-empty.
func readEHLO(t *testing.T, r *bufio.Reader, mustContain string) {
	t.Helper()
	found := mustContain == ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if mustContain != "" && len(line) >= len(mustContain) && strings.Contains(line, mustContain) {
			found = true
		}
		if strings.HasPrefix(line, "250 2.0.0") {
			if !found {
				t.Fatalf("EHLO missing %q", mustContain)
			}
			return
		}
		if strings.HasPrefix(line, "250 OK") && !strings.HasPrefix(line, "250-") {
			if !found {
				t.Fatalf("EHLO missing %q", mustContain)
			}
			return
		}
	}
}
