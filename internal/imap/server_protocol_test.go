package imap_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/imap"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

func startIMAPTestServer(t *testing.T) (context.Context, uint32, *mail.Inbox, net.Listener, func()) {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	dir := directory.NewLocal(store)
	acc, err := directory.SeedDev(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	srv := imap.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, imap.Options{})
	sctx, cancel := context.WithCancel(ctx)
	go func() { _ = srv.ServeListener(sctx, ln) }()
	time.Sleep(20 * time.Millisecond)
	cleanup := func() {
		cancel()
		_ = ln.Close()
		_ = store.Close()
	}
	return ctx, acc.ID, inbox, ln, cleanup
}

func TestIMAPAuthenticatePlainSASLIR(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "a1 CAPABILITY")
	expectPrefix(t, read, "* CAPABILITY IMAP4rev1 MOVE LITERAL+ SASL-IR AUTH=PLAIN")
	expectPrefix(t, read, "a1 OK")

	cred := base64.StdEncoding.EncodeToString([]byte("\x00alice@localhost\x00beaver"))
	send(t, conn, "a2 AUTHENTICATE PLAIN "+cred)
	expectPrefix(t, read, "a2 OK AUTHENTICATE completed")

	send(t, conn, "a3 CAPABILITY")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "* CAPABILITY") || !strings.Contains(line, "IDLE") || !strings.Contains(line, "NAMESPACE") {
		t.Fatalf("post-auth caps %q", line)
	}
	expectPrefix(t, read, "a3 OK")
}

func TestIMAPNamespace(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "n1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "n1 OK")
	send(t, conn, "n2 NAMESPACE")
	expectPrefix(t, read, `* NAMESPACE (("" "/")) NIL NIL`)
	expectPrefix(t, read, "n2 OK")
}

func TestIMAPRename(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "r1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "r1 OK")
	send(t, conn, "r2 CREATE OldName")
	expectPrefix(t, read, "r2 OK")
	send(t, conn, "r3 RENAME OldName NewName")
	expectPrefix(t, read, "r3 OK")
	send(t, conn, "r4 SELECT NewName")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "r4 OK")
	send(t, conn, "r5 RENAME INBOX Archive")
	expectPrefix(t, read, "r5 NO")
}

func TestIMAPAppendLiteralPlus(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "p1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "p1 OK")
	send(t, conn, "p2 SELECT Drafts")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "p2 OK")

	raw := []byte("From: a@b\r\nSubject: literal+\r\n\r\nbody\r\n")
	if _, err := fmt.Fprintf(conn, "p3 APPEND Drafts {%d+}\r\n", len(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "p3 OK")
}

func TestIMAPIdleDone(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "i1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "i1 OK")
	send(t, conn, "i2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "i2 OK")

	send(t, conn, "i3 IDLE")
	expectPrefix(t, read, "+ idling")
	send(t, conn, "DONE")
	expectPrefix(t, read, "i3 OK IDLE terminated")
}

func TestIMAPIdleExistsUpdate(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "i1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "i1 OK")
	send(t, conn, "i2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "i2 OK")

	// Sequential on purpose: reading the same bufio.Reader from two goroutines (and failing
	// from one after the test returned) made this test flaky.
	send(t, conn, "i3 IDLE")
	expectPrefix(t, read, "+ idling")
	if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\n\r\nidle\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatalf("waiting for EXISTS during IDLE: %v", err)
		}
		if strings.HasPrefix(line, "* 1 EXISTS") {
			break
		}
	}
	send(t, conn, "DONE")
	for {
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "i3 OK IDLE terminated") {
			return
		}
	}
}
