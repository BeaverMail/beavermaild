package imap_test

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/imap"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/security"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

func TestIMAPLoginAuthRateLimit(t *testing.T) {
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
	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	gate := security.NewRateLimitGate(security.RateLimitConfig{MaxAttempts: 2, Window: time.Minute})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := imap.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, imap.Options{AuthGate: gate})
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
	expectPrefix(t, read, "* OK")

	for i := 0; i < 2; i++ {
		tag := "l" + strconv.Itoa(i)
		send(t, conn, tag+" LOGIN alice@localhost wrong")
		expectPrefix(t, read, tag+" NO")
	}
	send(t, conn, "l3 LOGIN alice@localhost wrong")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if want := "l3 NO [LIMIT]"; len(line) < len(want) || line[:len(want)] != want {
		t.Fatalf("rate limit response %q", line)
	}
}
