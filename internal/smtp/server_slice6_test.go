package smtp_test

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/tlsload"
	"github.com/BeaverMail/beaver/internal/tlsload/tlstest"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestSMTPEHLOSlice6Extensions(t *testing.T) {
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
	send(t, conn, "EHLO test")
	seen := make(map[string]bool)
	for {
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"250-FUTURERELEASE",
			"250-DELIVER BY",
			"250-MT-PRIORITY",
			"250-NO-SOLICITING",
		} {
			if len(line) >= len(want) && line[:len(want)] == want {
				seen[want] = true
			}
		}
		if len(line) >= 7 && line[:7] == "250 2.0" {
			break
		}
	}
	for _, want := range []string{
		"250-FUTURERELEASE",
		"250-DELIVER BY",
		"250-MT-PRIORITY",
		"250-NO-SOLICITING",
	} {
		if !seen[want] {
			t.Fatalf("missing EHLO %s", want)
		}
	}
}

func TestSMTPVRFYDisabledByDefault(t *testing.T) {
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
	send(t, conn, "EHLO test")
	skipEHLOSlice6(t, read)
	send(t, conn, "VRFY alice@localhost")
	expect(t, read, "252")
}

func TestSMTPVRFYEnabled(t *testing.T) {
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
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{VRFYEnabled: true})
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
	var sawVRFY bool
	for {
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if len(line) >= 8 && line[:8] == "250-VRFY" {
			sawVRFY = true
		}
		if len(line) >= 7 && line[:7] == "250 2.0" {
			break
		}
	}
	if !sawVRFY {
		t.Fatal("EHLO missing VRFY")
	}
	send(t, conn, "VRFY alice@localhost")
	expect(t, read, "250 2.1.5")
	send(t, conn, "VRFY nobody@localhost")
	expect(t, read, "550 5.1.1")
}

func TestSMTPRejectFutureReleaseHold(t *testing.T) {
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
	send(t, conn, "EHLO test")
	skipEHLOSlice6(t, read)
	send(t, conn, "MAIL FROM:<sender@example.com> HOLD=20260101000000")
	expect(t, read, "555 5.5.4")
}

func TestSMTPRejectDeliverBy(t *testing.T) {
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
	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"localhost"})
	certs, err := tlsload.Load(certFile, keyFile, "1.2")
	if err != nil {
		t.Fatal(err)
	}

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)

	tlsLn, err := certs.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, inbox, queue, "", "", smtp.Options{Certs: certs})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeSubmissionListener(sctx, tlsLn, true) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := tlsload.DialTestClient(tlsLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO test")
	skipEHLOSlice6(t, read)
	send(t, conn, "AUTH PLAIN "+plainCred("alice@localhost", directory.SeedPassword()))
	expect(t, read, "235")
	send(t, conn, "MAIL FROM:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<remote@example.com> BY=20260101000000")
	expect(t, read, "555 5.5.4")
}

func TestSMTPBody8BitMIMEQueued(t *testing.T) {
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
	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"localhost"})
	certs, err := tlsload.Load(certFile, keyFile, "1.2")
	if err != nil {
		t.Fatal(err)
	}

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)

	tlsLn, err := certs.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, inbox, queue, "", "", smtp.Options{Certs: certs})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeSubmissionListener(sctx, tlsLn, true) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := tlsload.DialTestClient(tlsLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO test")
	skipEHLOSlice6(t, read)
	send(t, conn, "AUTH PLAIN "+plainCred("alice@localhost", directory.SeedPassword()))
	expect(t, read, "235")
	send(t, conn, "MAIL FROM:<alice@localhost> BODY=8BITMIME")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<remote@example.com>")
	expect(t, read, "250")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: eight")
	send(t, conn, "")
	send(t, conn, "café")
	send(t, conn, ".")
	expect(t, read, "250")

	all, err := queue.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Msg.Body != "8BITMIME" {
		t.Fatalf("queue body %q entries %d", all[0].Msg.Body, len(all))
	}
}

func skipEHLOSlice6(t *testing.T, read *bufio.Reader) {
	t.Helper()
	for {
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if len(line) >= 7 && line[:7] == "250 2.0" {
			return
		}
	}
}
