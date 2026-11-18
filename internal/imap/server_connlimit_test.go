package imap_test

import (
	"bufio"
	"context"
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

func TestIMAPMaxConnections(t *testing.T) {
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
	srv := imap.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, imap.Options{MaxConnections: 1})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeListener(sctx, ln) }()
	time.Sleep(20 * time.Millisecond)

	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	r1 := bufio.NewReader(c1)
	line, err := r1.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "* OK") {
		t.Fatalf("greeting: %q err=%v", line, err)
	}

	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err = bufio.NewReader(c2).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "Too many connections") {
		t.Fatalf("want bye too many, got %q", line)
	}
}

func TestIMAPReadTimeout(t *testing.T) {
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
	srv := imap.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, imap.Options{ReadTimeout: 80 * time.Millisecond})
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
	line, err := read.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "* OK") {
		t.Fatalf("greeting: %q err=%v", line, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = read.ReadString('\n')
	if err == nil {
		t.Fatal("expected connection close after idle read timeout")
	}
}

// One account from one address holds at most 10 logged-in sessions (Dovecot's
// mail_max_userip_connections); the 11th login gets NO [LIMIT] and one more fits once a session
// closes. RFC 5465 9: each NOTIFY session also costs a mailbox list read every second.
func TestIMAPSessionsPerUserIP(t *testing.T) {
	t.Parallel()
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	login := func() (net.Conn, string) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(c)
		expectPrefix(t, r, "* OK")
		send(t, c, "l1 LOGIN alice@localhost beaver")
		line, _ := r.ReadString('\n')
		return c, line
	}
	var conns []net.Conn
	for i := range 10 {
		c, line := login()
		if !strings.HasPrefix(line, "l1 OK") {
			t.Fatalf("login %d: %q", i+1, line)
		}
		conns = append(conns, c)
	}
	if _, line := login(); !strings.HasPrefix(line, "l1 NO [LIMIT]") {
		t.Fatalf("11th login: %q", line)
	}
	conns[0].Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, line := login()
		if strings.HasPrefix(line, "l1 OK") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot not freed after a session closed: %q", line)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
