package smtp_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
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

// spoolServer starts a server with the default message limit (10 MB) delivering to alice.
func spoolServer(t *testing.T) (net.Conn, *bufio.Reader) {
	t.Helper()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{})
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = srv.ServeListener(sctx, ln) }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	r := bufio.NewReader(conn)
	expect(t, r, "220")
	send(t, conn, "EHLO test")
	readEHLO(t, r, "CHUNKING")
	return conn, r
}

// peakHeap runs fn and returns how much the heap in use grew at its highest, sampled meanwhile.
func peakHeap(fn func()) uint64 {
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	peak := before.HeapInuse
	stop, done := make(chan bool), make(chan bool)
	go func() {
		defer close(done)
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			peak = max(peak, m.HeapInuse)
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	fn()
	close(stop)
	<-done
	return peak - before.HeapInuse
}

// CVE-2026-45713 class (Mailpit): a message is received to disk, not memory. A 9 MB message, by
// DATA or BDAT, accepted or over the limit, must not raise the heap by its size (the pipeline held
// it about four times over: 43 MB).
func TestMessageSpooledToDisk(t *testing.T) {
	body := strings.Repeat("lorem ipsum dolor sit amet consectetur adipiscing\r\n", 190000) // ~9.7 MB
	data := []byte("From: a@example.org\r\nSubject: big\r\n\r\n" + body + ".\r\n")
	bdat := []byte("From: a@example.org\r\nSubject: big\r\n\r\n" + body)
	tooBig := []byte("From: a@example.org\r\n\r\n" + body + body + ".\r\n")
	body = ""
	for _, tc := range []struct {
		name, cmd string
		payload   []byte
		want      string
	}{
		{"DATA accepted", "DATA", data, "250"},
		{"BDAT accepted", fmt.Sprintf("BDAT %d LAST", len(bdat)), bdat, "250"},
		{"DATA over the limit", "DATA", tooBig, "552"},
	} {
		conn, r := spoolServer(t)
		send(t, conn, "MAIL FROM:<x@example.org>")
		expect(t, r, "250")
		send(t, conn, "RCPT TO:<alice@localhost>")
		expect(t, r, "250")
		send(t, conn, tc.cmd)
		if tc.cmd == "DATA" {
			expect(t, r, "354")
		}
		grown := peakHeap(func() {
			if _, err := conn.Write(tc.payload); err != nil {
				t.Fatal(err)
			}
			expect(t, r, tc.want)
		})
		if grown > 4<<20 {
			t.Errorf("%s: heap grew %d MB for a %d MB message", tc.name, grown>>20, len(tc.payload)>>20)
		}
	}
}

// A header block past 1 MiB is refused like a message too large, and the session stays in step:
// the rest of the message is read and dropped, and the next command is answered.
func TestHeaderTooLarge(t *testing.T) {
	t.Parallel()
	header := strings.Repeat("X-Filler: "+strings.Repeat("x", 90)+"\r\n", 11000) // ~1.1 MB
	conn, r := spoolServer(t)
	send(t, conn, "MAIL FROM:<x@example.org>")
	expect(t, r, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, r, "250")
	send(t, conn, "DATA")
	expect(t, r, "354")
	if _, err := conn.Write([]byte(header + "\r\nbody\r\n.\r\n")); err != nil {
		t.Fatal(err)
	}
	expect(t, r, "552")
	send(t, conn, "NOOP")
	expect(t, r, "250")

	// BDAT: the chunk that crosses the limit is dropped whole; LAST then gets 552 too.
	send(t, conn, "MAIL FROM:<x@example.org>")
	expect(t, r, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, r, "250")
	chunk := header + "\r\nbody\r\n"
	if _, err := conn.Write([]byte(fmt.Sprintf("BDAT %d\r\n%s", len(chunk), chunk))); err != nil {
		t.Fatal(err)
	}
	expect(t, r, "552")
	send(t, conn, "NOOP")
	expect(t, r, "250")
}

// A spool that cannot be written (here a read-only store directory; a full disk alike) is a local
// error: 451 before any data is asked for, never the error text, which names a file.
func TestSpoolFailureIsLocalError(t *testing.T) {
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
	root := t.TempDir() + "/blobs"
	if err := os.Mkdir(root, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, mail.NewInbox(store, blob.NewFS(root)), nil, "", "", smtp.Options{})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeListener(sctx, ln) }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	expect(t, r, "220")
	send(t, conn, "EHLO test")
	readEHLO(t, r, "CHUNKING")
	send(t, conn, "MAIL FROM:<x@example.org>")
	expect(t, r, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, r, "250")
	send(t, conn, "DATA")
	expect(t, r, "451 4.3.0 Local error in processing")
	send(t, conn, "BDAT 5 LAST\r\nhello")
	expect(t, r, "451 4.3.0 Local error in processing")
	send(t, conn, "NOOP")
	expect(t, r, "250")
}
