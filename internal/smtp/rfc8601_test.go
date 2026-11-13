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
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// A6 (RFC 8601 audit, §5 MUST): a field claiming our authserv-id is removed even when mail-auth is
// off and we add none of our own. Before, removal only ran together with our own field.
func TestRFC8601StripsForgedWithoutMailAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	acc, err := directory.SeedDev(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, inbox, mail.NewQueue(store, blobs), "", "", smtp.Options{Hostname: "mx.example.net"})
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = srv.ServeListener(sctx, ln) }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	for _, st := range []struct{ send, want string }{
		{"EHLO client.example.org", ""},
		{"MAIL FROM:<bob@example.org>", "250"},
		{"RCPT TO:<alice@localhost>", "250"},
		{"DATA", "354"},
	} {
		send(t, conn, st.send)
		if st.want == "" {
			readEHLO(t, read, "")
			continue
		}
		expect(t, read, st.want)
	}
	send(t, conn, "Authentication-Results: mx.example.net; dkim=pass header.d=bank.example")
	send(t, conn, "Authentication-Results: mx.other.example; spf=pass smtp.mailfrom=example.org")
	send(t, conn, "From: <bob@example.org>")
	send(t, conn, "")
	send(t, conn, "body")
	send(t, conn, ".")
	expect(t, read, "250")

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("inbox %d, %v", len(msgs), err)
	}
	raw, err := inbox.LoadRaw(ctx, msgs[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if strings.Contains(got, "mx.example.net; dkim=pass") || !strings.Contains(got, "Authentication-Results: mx.other.example;") {
		t.Fatalf("forged field kept or foreign one dropped:\n%s", got)
	}
}
