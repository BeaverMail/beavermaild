package imap_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
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

func TestIMAPFetchInbox(t *testing.T) {
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
	raw := []byte("From: a@b\r\nSubject: hi\r\n\r\nhello imap\r\n")
	if _, err := inbox.Deliver(ctx, acc.ID, raw); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := imap.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, imap.Options{})
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
	send(t, conn, "a1 CAPABILITY")
	expectPrefix(t, read, "* CAPABILITY")
	expectPrefix(t, read, "a1 OK")
	send(t, conn, "a2 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "a2 OK")
	send(t, conn, "a3 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "a3 OK")
	send(t, conn, "a4 FETCH 1 (UID RFC822.SIZE BODY[])")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	// One FETCH response: plain items then the literal (RFC 3501; as Dovecot/Gmail).
	if !strings.HasPrefix(line, "* 1 FETCH (UID 1 RFC822.SIZE ") || !strings.Contains(line, " BODY[] {") {
		t.Fatalf("fetch %q", line)
	}
	n, err := literalSize(line)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(read, body); err != nil {
		t.Fatal(err)
	}
	if string(body) != string(raw) {
		t.Fatalf("body %q want %q", body, raw)
	}
	expectPrefix(t, read, ")")
	expectPrefix(t, read, "a4 OK")
	send(t, conn, "a5 STORE 1 +FLAGS (\\Seen)")
	line, err = read.ReadString('\n')
	if err != nil || !strings.Contains(line, `FLAGS (\Seen)`) {
		t.Fatalf("store response %q err %v", line, err)
	}
	expectPrefix(t, read, "a5 OK")
	send(t, conn, "a6 FETCH 1 (FLAGS)")
	line, err = read.ReadString('\n')
	if err != nil || !strings.Contains(line, `FLAGS (\Seen)`) || !strings.Contains(line, "MODSEQ (") {
		t.Fatalf("fetch flags %q err %v", line, err)
	}
	expectPrefix(t, read, "a6 OK")
	send(t, conn, "a7 SEARCH ALL")
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "a7 OK")
	send(t, conn, "a8 SEARCH UNSEEN")
	expectPrefix(t, read, "* SEARCH")
	expectPrefix(t, read, "a8 OK")
	send(t, conn, "a9 UID FETCH 1 (UID FLAGS)")
	line, err = read.ReadString('\n')
	if err != nil || !strings.Contains(line, "UID 1") || !strings.Contains(line, `FLAGS (\Seen)`) || !strings.Contains(line, "MODSEQ (") {
		t.Fatalf("uid fetch %q err %v", line, err)
	}
	expectPrefix(t, read, "a9 OK")
	send(t, conn, "aa LIST \"\" \"*\"")
	expectPrefix(t, read, "* LIST")
	expectPrefix(t, read, "* LIST")
	expectPrefix(t, read, "* LIST")
	expectPrefix(t, read, "* LIST")
	expectPrefix(t, read, "aa OK")
	send(t, conn, "ab SELECT Sent")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "ab OK")
	send(t, conn, "ac STATUS INBOX (MESSAGES UNSEEN UIDNEXT UIDVALIDITY)")
	expectPrefix(t, read, "* STATUS INBOX (MESSAGES 1 UNSEEN 0 UIDNEXT 2 UIDVALIDITY 1)")
	expectPrefix(t, read, "ac OK")
	send(t, conn, "ad CREATE Archive")
	expectPrefix(t, read, "ad OK")
	send(t, conn, "ae SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "ae OK")
	send(t, conn, "af MOVE 1 Trash")
	expectPrefix(t, read, "af OK")
	send(t, conn, "ag SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "ag OK")
	send(t, conn, "ah SELECT Trash")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "ah OK")
	send(t, conn, "ai EXAMINE Trash")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "ai OK [READ-ONLY]")
	send(t, conn, "aj LOGOUT")
}

func TestIMAPAppendCreatesMailbox(t *testing.T) {
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

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	srv := imap.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, imap.Options{})
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
	send(t, conn, "a1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "a1 OK")

	send(t, conn, "a2 SELECT Queue")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "a2 OK")

	raw := []byte("From: a@b\r\nSubject: queued\r\n\r\noutbox\r\n")
	if _, err := fmt.Fprintf(conn, "a3 APPEND Queue (\\Seen) {%d}\r\n", len(raw)); err != nil {
		t.Fatal(err)
	}
	expectPrefix(t, read, "+")
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("\r\n")); err != nil {
		t.Fatal(err)
	}
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "a3 OK")

	send(t, conn, "a4 SELECT Queue")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "a4 OK")
}

func TestIMAPExpungeDeleted(t *testing.T) {
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
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\none\r\n")); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := imap.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, imap.Options{})
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
	send(t, conn, "b1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "b1 OK")
	send(t, conn, "b2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "b2 OK")
	send(t, conn, "b3 STORE 1 +FLAGS (\\Deleted)")
	line, err := read.ReadString('\n')
	if err != nil || !strings.Contains(line, `FLAGS (\Deleted)`) {
		t.Fatalf("store response %q err %v", line, err)
	}
	expectPrefix(t, read, "b3 OK")
	send(t, conn, "b4 EXPUNGE")
	expectPrefix(t, read, "* 1 EXPUNGE")
	expectPrefix(t, read, "b4 OK")
	send(t, conn, "b5 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "b5 OK")
}

func literalSize(line string) (int, error) {
	i := strings.LastIndex(line, "{")
	j := strings.LastIndex(line, "}")
	if i < 0 || j <= i {
		return 0, fmt.Errorf("imap: no literal size in %q", line)
	}
	size := strings.TrimSuffix(line[i+1:j], "+")
	return strconv.Atoi(size)
}

func send(t *testing.T, conn net.Conn, line string) {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil {
		t.Fatal(err)
	}
}

// expectSelectOK consumes the untagged "* OK [code]" lines a SELECT/EXAMINE sends before its tagged reply.
func expectSelectOK(t *testing.T, r *bufio.Reader) {
	t.Helper()
	expectPrefix(t, r, "* OK [UIDVALIDITY")
	for {
		b, err := r.Peek(6)
		if err != nil || string(b) != "* OK [" {
			return
		}
		if _, err := r.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
	}
}

func expectPrefix(t *testing.T, r *bufio.Reader, prefix string) {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("line %q want prefix %q", line, prefix)
	}
}
