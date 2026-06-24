package smtp_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
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

func plainCred(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + pass))
}

func TestSMTPSubmissionTLSAuth(t *testing.T) {
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
	readEHLO(t, read, "AUTH PLAIN")

	cred := plainCred("alice@localhost", directory.SeedPassword())
	send(t, conn, "AUTH PLAIN "+cred)
	expect(t, read, "235")

	send(t, conn, "MAIL FROM:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<bob@example.com>")
	expect(t, read, "250")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: auth test")
	send(t, conn, "")
	send(t, conn, "body")
	send(t, conn, ".")
	expect(t, read, "250")
	send(t, conn, "QUIT")
}

func TestSMTPSubmissionRequiresAuth(t *testing.T) {
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

	tlsLn, err := certs.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, inbox, nil, "", "", smtp.Options{Certs: certs})
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
	readEHLO(t, read, "AUTH PLAIN")
	send(t, conn, "MAIL FROM:<alice@localhost>")
	expect(t, read, "530")
}

func TestSMTPSubmissionAuthBadPassword(t *testing.T) {
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

	tlsLn, err := certs.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, inbox, nil, "", "", smtp.Options{Certs: certs})
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
	readEHLO(t, read, "AUTH PLAIN")
	send(t, conn, "AUTH PLAIN "+plainCred("alice@localhost", "wrong"))
	expect(t, read, "535")
}

func TestSMTPSubmissionSenderMismatch(t *testing.T) {
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

	tlsLn, err := certs.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, inbox, nil, "", "", smtp.Options{Certs: certs})
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
	readEHLO(t, read, "AUTH PLAIN")
	send(t, conn, "AUTH PLAIN "+plainCred("alice@localhost", directory.SeedPassword()))
	expect(t, read, "235")
	send(t, conn, "MAIL FROM:<other@example.com>")
	expect(t, read, "553")
}

func TestSMTPSubmissionPlaceholderMailFrom(t *testing.T) {
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
	readEHLO(t, read, "AUTH PLAIN")
	send(t, conn, "AUTH PLAIN "+plainCred("alice@localhost", directory.SeedPassword()))
	expect(t, read, "235")
	send(t, conn, "MAIL FROM:<unknown@localhost>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<bob@example.com>")
	expect(t, read, "250")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: placeholder from")
	send(t, conn, "")
	send(t, conn, "body")
	send(t, conn, ".")
	expect(t, read, "250")

	pending, err := queue.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Msg.ReturnPath != "alice@localhost" {
		t.Fatalf("return path %+v", pending)
	}
}

func TestSMTPSubmissionSTARTTLSAuth(t *testing.T) {
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

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, inbox, nil, "", "", smtp.Options{Certs: certs})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeSubmissionListener(sctx, ln, false) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO test")
	readEHLO(t, read, "STARTTLS")
	send(t, conn, "AUTH PLAIN "+plainCred("alice@localhost", directory.SeedPassword()))
	expect(t, read, "538")

	send(t, conn, "STARTTLS")
	expect(t, read, "220")
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	read = bufio.NewReader(tlsConn)
	send(t, tlsConn, "EHLO test")
	readEHLO(t, read, "AUTH PLAIN")
	send(t, tlsConn, "AUTH PLAIN "+plainCred("alice@localhost", directory.SeedPassword()))
	expect(t, read, "235")
}

func TestSMTPInboundNoAuth(t *testing.T) {
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
	readEHLO(t, read, "")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expect(t, read, "250")
}
