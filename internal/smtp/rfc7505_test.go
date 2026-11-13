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

// RFC 7505 4.1: on port 25 a sender whose domain publishes a null MX gets 550 5.7.27 (nullmx.test in
// the stub resolver of TestMain); other senders and the null reverse path are unaffected.
func TestRFC7505SenderNullMX(t *testing.T) {
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, mail.NewInbox(store, blobs), mail.NewQueue(store, blobs), "", "", smtp.Options{})
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
	send(t, conn, "EHLO client.example.org")
	readEHLO(t, read, "")
	for _, st := range []struct{ send, want string }{
		{"MAIL FROM:<bob@nullmx.test>", "550 5.7.27"},
		{"MAIL FROM:<bob@NULLMX.test>", "550 5.7.27"},
		{"MAIL FROM:<>", "250"},
		{"RSET", "250"},
		{"MAIL FROM:<bob@example.org>", "250"},
	} {
		send(t, conn, st.send)
		expect(t, read, st.want)
	}
}
