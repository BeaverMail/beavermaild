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
)

// An alias fans out to its targets, and a mailbox addressed both directly and through an alias
// gets one copy.
func TestSMTPAliasDelivery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	alice, err := directory.SeedDev(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := dir.CreateAccountRole(ctx, alice.DomainID, "bob", "pw", directory.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAlias(ctx, "localhost", "team", []string{"alice@localhost", "bob@localhost"}); err != nil {
		t.Fatal(err)
	}
	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))

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
	send(t, conn, "RCPT TO:<team@localhost>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<nobody@localhost>")
	expect(t, read, "550")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: hi")
	send(t, conn, "")
	send(t, conn, "hello team")
	send(t, conn, ".")
	expect(t, read, "250")
	send(t, conn, "QUIT")

	for name, id := range map[string]uint32{"alice": alice.ID, "bob": bob.ID} {
		msgs, err := inbox.List(ctx, id, mail.InboxMailboxID)
		if err != nil {
			t.Fatal(err)
		}
		if len(msgs) != 1 {
			t.Fatalf("%s got %d messages, want 1", name, len(msgs))
		}
	}
}
