package smtp_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

func TestSMTPHelpVrfyExpn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dir := directory.NewLocal(store)
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
	send(t, conn, "HELP")
	for {
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "214 2.0.0") {
			break
		}
		if !strings.HasPrefix(line, "214") {
			t.Fatalf("HELP line %q", line)
		}
	}
	send(t, conn, "VRFY alice@localhost")
	expect(t, read, "252")
	send(t, conn, "EXPN all")
	expect(t, read, "252")
	send(t, conn, "ETRN queue")
	expect(t, read, "502")
}

func TestSMTPBDATDeliver(t *testing.T) {
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
	send(t, conn, "EHLO test")
	readEHLO(t, read, "CHUNKING")
	send(t, conn, "MAIL FROM:<sender@example.com> RET=FULL ENVID=xyz")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<alice@localhost> NOTIFY=FAILURE")
	expect(t, read, "250")

	body := "Subject: bdat\r\n\r\nchunked"
	// RFC 3030: command line, then exactly len(body) bytes (no CRLF after), then one reply.
	if _, err := fmt.Fprintf(conn, "BDAT %d LAST\r\n%s", len(body), body); err != nil {
		t.Fatal(err)
	}
	expect(t, read, "250")

	key := storage.AppendKey(nil, storage.SubspaceMail, 1, 1, byte(storage.CollectionEmail), nil)
	if _, err := store.Get(ctx, key); err != nil {
		t.Fatalf("email not stored: %v", err)
	}
}

func TestSMTPBDATMultiChunk(t *testing.T) {
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

	// Each chunk is the command line plus exactly n bytes; the reply follows the chunk.
	part1 := "Subject: x\r\n\r\npart-1-"
	part2 := "part-2"
	if _, err := fmt.Fprintf(conn, "BDAT %d\r\n%s", len(part1), part1); err != nil {
		t.Fatal(err)
	}
	expect(t, read, "250")
	if _, err := fmt.Fprintf(conn, "BDAT %d LAST\r\n%s", len(part2), part2); err != nil {
		t.Fatal(err)
	}
	expect(t, read, "250")

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("inbox %d messages, err %v", len(msgs), err)
	}
	raw, err := inbox.LoadRaw(ctx, msgs[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "part-1-part-2") {
		t.Fatalf("stored %q", raw)
	}
}

// Our client delivering to our server over CHUNKING+PIPELINING, as Gmail does inbound.
func TestSMTPClientToServerBDAT(t *testing.T) {
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

	body := "Subject: e2e\r\n\r\nhello over bdat\r\n"
	reply, err := smtp.SendReply(ctx, ln.Addr().String(), "sender@example.com", "alice@localhost", []byte(body), smtp.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(reply, "250") {
		t.Fatalf("reply %q", reply)
	}
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("inbox %d messages, err %v", len(msgs), err)
	}
}

func TestClientEHLOSizeAnd8BITMIME(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var mailLine string
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		reply(conn, "220 mx.test ESMTP\r\n")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "EHLO"):
				reply(conn, "250-mx.test\r\n250-8BITMIME\r\n250-SIZE 65536\r\n250 2.0.0 Ok\r\n")
			case strings.HasPrefix(line, "MAIL"):
				mailLine = line
				reply(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "RCPT"):
				reply(conn, "250 OK\r\n")
			case line == "DATA":
				inData = true
				reply(conn, "354 go\r\n")
			case inData:
				if line == "." {
					inData = false
					reply(conn, "250 queued\r\n")
				}
			case strings.HasPrefix(line, "QUIT"):
				reply(conn, "221 bye\r\n")
				return
			}
		}
	}()

	ctx := context.Background()
	data := []byte("eight-bit body\r\n")
	err = smtp.Send(ctx, ln.Addr().String(), "sender@example.com", "rcpt@example.com", data, smtp.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if !strings.Contains(mailLine, "SIZE=16") {
		t.Fatalf("MAIL line %q missing SIZE", mailLine)
	}
	if !strings.Contains(mailLine, "BODY=8BITMIME") {
		t.Fatalf("MAIL line %q missing 8BITMIME", mailLine)
	}
}
