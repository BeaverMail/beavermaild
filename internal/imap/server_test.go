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
	expectPrefix(t, read, "* 0 RECENT")
	expectPrefix(t, read, "* OK [UIDVALIDITY")
	expectPrefix(t, read, "a3 OK")
	send(t, conn, "a4 FETCH 1 (UID RFC822.SIZE BODY[])")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "* 1 FETCH") || !strings.Contains(line, "BODY[]") {
		t.Fatalf("fetch prelude %q", line)
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
	expectPrefix(t, read, "* 1 FETCH (FLAGS (\\Seen))")
	expectPrefix(t, read, "a5 OK")
	send(t, conn, "a6 FETCH 1 (FLAGS)")
	expectPrefix(t, read, "* 1 FETCH (FLAGS (\\Seen))")
	expectPrefix(t, read, "a6 OK")
	send(t, conn, "a7 SEARCH ALL")
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "a7 OK")
	send(t, conn, "a8 SEARCH UNSEEN")
	expectPrefix(t, read, "* SEARCH")
	expectPrefix(t, read, "a8 OK")
	send(t, conn, "a9 UID FETCH 1 (UID FLAGS)")
	expectPrefix(t, read, "* 1 FETCH (UID 1 FLAGS (\\Seen))")
	expectPrefix(t, read, "a9 OK")
	send(t, conn, "aa LIST \"\" \"*\"")
	expectPrefix(t, read, "* LIST")
	expectPrefix(t, read, "* LIST")
	expectPrefix(t, read, "* LIST")
	expectPrefix(t, read, "aa OK")
	send(t, conn, "ab SELECT Sent")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectPrefix(t, read, "* OK [UIDVALIDITY")
	expectPrefix(t, read, "ab OK")
	send(t, conn, "ac STATUS INBOX (MESSAGES UNSEEN UIDNEXT UIDVALIDITY)")
	expectPrefix(t, read, "* STATUS INBOX (MESSAGES 1 UNSEEN 0 UIDNEXT 2 UIDVALIDITY 1)")
	expectPrefix(t, read, "ac OK")
	send(t, conn, "ad CREATE Drafts")
	expectPrefix(t, read, "ad OK")
	send(t, conn, "ae SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectPrefix(t, read, "* OK [UIDVALIDITY")
	expectPrefix(t, read, "ae OK")
	send(t, conn, "af MOVE 1 Trash")
	expectPrefix(t, read, "af OK")
	send(t, conn, "ag SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectPrefix(t, read, "* OK [UIDVALIDITY")
	expectPrefix(t, read, "ag OK")
	send(t, conn, "ah SELECT Trash")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectPrefix(t, read, "* OK [UIDVALIDITY")
	expectPrefix(t, read, "ah OK")
	send(t, conn, "ai EXAMINE Trash")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectPrefix(t, read, "* OK [UIDVALIDITY")
	expectPrefix(t, read, "ai OK [READ-ONLY]")
	send(t, conn, "aj LOGOUT")
}

func literalSize(line string) (int, error) {
	i := strings.LastIndex(line, "{")
	j := strings.LastIndex(line, "}")
	if i < 0 || j <= i {
		return 0, fmt.Errorf("imap: no literal size in %q", line)
	}
	return strconv.Atoi(line[i+1 : j])
}

func send(t *testing.T, conn net.Conn, line string) {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil {
		t.Fatal(err)
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
