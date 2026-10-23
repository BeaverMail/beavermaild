package imap_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/imap"
	"github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

// startIMAPWithTimeout serves with a production-like idle timeout and returns a stop func
// that cancels Serve and reports how long it took to return.
func startIMAPWithTimeout(t *testing.T) (*mail.Inbox, uint32, string, func() time.Duration) {
	t.Helper()
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
	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := imap.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, imap.Options{ReadTimeout: 30 * time.Minute})
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = srv.ServeListener(sctx, ln); close(done) }()
	t.Cleanup(cancel)
	time.Sleep(20 * time.Millisecond)
	stop := func() time.Duration {
		start := time.Now()
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Serve did not return")
		}
		return time.Since(start)
	}
	return inbox, acc.ID, ln.Addr().String(), stop
}

func loginSelect(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "a1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "a1 OK")
	send(t, conn, "a2 SELECT INBOX")
	for {
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "a2 OK") {
			return conn, read
		}
	}
}

// On shutdown every session, idle at the prompt or in IDLE, gets BYE before the conn closes.
func TestIMAPShutdownSendsBye(t *testing.T) {
	t.Parallel()
	_, _, addr, stop := startIMAPWithTimeout(t)

	promptConn, promptRead := loginSelect(t, addr)
	idleConn, idleRead := loginSelect(t, addr)
	send(t, idleConn, "i1 IDLE")
	expectPrefix(t, idleRead, "+ idling")

	if took := stop(); took > 3*time.Second {
		t.Fatalf("drain took %s", took)
	}
	// Time the BYE from shutdown, not from login: a loaded machine can spend the login deadline on setup.
	for _, c := range []net.Conn{promptConn, idleConn} {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	expectPrefix(t, promptRead, "* BYE [UNAVAILABLE]")
	expectPrefix(t, idleRead, "* BYE [UNAVAILABLE]")
}

// With an idle timeout configured (production default), IDLE must still push new mail.
func TestIMAPIdlePushWithReadTimeout(t *testing.T) {
	t.Parallel()
	inbox, accID, addr, _ := startIMAPWithTimeout(t)

	conn, read := loginSelect(t, addr)
	send(t, conn, "i1 IDLE")
	expectPrefix(t, read, "+ idling")
	if _, err := inbox.Deliver(context.Background(), accID, []byte("Subject: new\r\n\r\nhi\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := read.ReadString('\n')
	if err != nil || !strings.Contains(line, "EXISTS") {
		t.Fatalf("no EXISTS push during IDLE: %q %v", line, err)
	}
}
