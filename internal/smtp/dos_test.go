package smtp_test

import (
	"bufio"
	"context"
	"net"
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

// inboundServer starts a port 25 server and returns its address.
func inboundServer(t *testing.T, opts smtp.Options) string {
	t.Helper()
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, mail.NewInbox(store, blobs), mail.NewQueue(store, blobs), "", "", opts)
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = srv.ServeListener(sctx, ln) }()
	return ln.Addr().String()
}

func dialInbound(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, bufio.NewReader(conn)
}

// Loopback (a local proxy or reinjecting filter) is exempt from the per-address cap.
func TestInboundConnectionsPerIPLoopbackExempt(t *testing.T) {
	t.Parallel()
	addr := inboundServer(t, smtp.Options{MaxConnectionsPerIP: 1})
	for range 3 {
		_, read := dialInbound(t, addr)
		expect(t, read, "220")
	}
}

// S1 of the RFC 7505 review: a malformed sender domain is not looked up (Go would answer "not found"
// without the DNS and the answer would fill the cache). Here a 300-octet label under nullmx.test
// would get 550 5.7.27 if it were checked.
func TestInboundNullMXSkipsMalformedDomain(t *testing.T) {
	t.Parallel()
	conn, read := dialInbound(t, inboundServer(t, smtp.Options{}))
	expect(t, read, "220")
	send(t, conn, "EHLO client.example.org")
	readEHLO(t, read, "")
	send(t, conn, "MAIL FROM:<x@"+strings.Repeat("a", 300)+".nullmx.test>")
	expect(t, read, "250")
}

// A session that keeps opening transactions that deliver nothing is closed before it makes us query
// the DNS without end (every MAIL runs SPF and the null MX check).
func TestInboundIdleMailLimit(t *testing.T) {
	t.Parallel()
	conn, read := dialInbound(t, inboundServer(t, smtp.Options{}))
	expect(t, read, "220")
	send(t, conn, "EHLO client.example.org")
	readEHLO(t, read, "")
	// One delivered message raises the allowance by one.
	send(t, conn, "MAIL FROM:<bob@example.org>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "From: <bob@example.org>")
	send(t, conn, "")
	send(t, conn, "hi")
	send(t, conn, ".")
	expect(t, read, "250")
	for range smtp.MaxIdleMail {
		send(t, conn, "MAIL FROM:<x@throwaway.example.org>")
		expect(t, read, "250")
		send(t, conn, "RSET")
		expect(t, read, "250")
	}
	send(t, conn, "MAIL FROM:<x@throwaway.example.org>")
	expect(t, read, "421 4.7.0 Too many transactions")
}
