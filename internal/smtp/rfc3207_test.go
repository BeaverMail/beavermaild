package smtp_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
	"github.com/BeaverMail/beavermaild/internal/tlsload/tlstest"
)

// RFC 3207 4: STARTTLS takes no parameters (501), and a server that requires TLS, as submission
// does since AUTH needs it, answers 530 5.7.0 to every command but NOOP, EHLO, STARTTLS and QUIT
// (AUTH keeps 538 5.7.11, RFC 4954 6).
func TestRFC3207SubmissionBeforeTLS(t *testing.T) {
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, mail.NewInbox(store, blobs), mail.NewQueue(store, blobs), "", "", smtp.Options{Certs: certs})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeSubmissionListener(sctx, ln, false) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO test")
	readEHLO(t, read, "STARTTLS")
	for _, st := range []struct{ send, want string }{
		{"HELO test", "530 5.7.0"},
		{"MAIL FROM:<alice@localhost>", "530 5.7.0"},
		{"RCPT TO:<alice@localhost>", "530 5.7.0"},
		{"DATA", "530 5.7.0"},
		{"VRFY alice", "530 5.7.0"},
		{"HELP", "530 5.7.0"},
		{"RSET", "530 5.7.0"},
		{"AUTH PLAIN AGFsaWNlAHg=", "538 5.7.11"},
		{"NOOP", "250"},
		{"STARTTLS now", "501"},
		{"STARTTLS", "220"},
	} {
		send(t, conn, st.send)
		expect(t, read, st.want)
	}
}

// RFC 3207 6: a server MUST be configurable to require TLS from selected clients. Clients in
// smtp.require_starttls_from get 530 before STARTTLS on port 25 and mail after it; other clients are
// unaffected (RFC 3207 4: a public MX MUST NOT require TLS).
func TestRFC3207RequireSTARTTLSFrom(t *testing.T) {
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
	serve := func(prefix string) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, mail.NewInbox(store, blobs), mail.NewQueue(store, blobs), "", "", smtp.Options{
			Certs: certs, RequireSTARTTLSFrom: []netip.Prefix{netip.MustParsePrefix(prefix)},
		})
		sctx, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)
		go func() { _ = srv.ServeListener(sctx, ln) }()
		return ln.Addr().String()
	}
	dial := func(addr string) (net.Conn, *bufio.Reader) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		read := bufio.NewReader(conn)
		expect(t, read, "220")
		send(t, conn, "EHLO test")
		readEHLO(t, read, "STARTTLS")
		return conn, read
	}

	conn, read := dial(serve("127.0.0.0/8"))
	for _, st := range []struct{ send, want string }{
		{"MAIL FROM:<bob@example.org>", "530 5.7.0"},
		{"RCPT TO:<alice@localhost>", "530 5.7.0"},
		{"RSET", "530 5.7.0"},
		{"NOOP", "250"},
		{"STARTTLS", "220"},
	} {
		send(t, conn, st.send)
		expect(t, read, st.want)
	}
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	tread := bufio.NewReader(tc)
	send(t, tc, "EHLO test")
	readEHLO(t, tread, "")
	send(t, tc, "MAIL FROM:<bob@example.org>")
	expect(t, tread, "250")

	conn, read = dial(serve("192.0.2.0/24")) // another network: no requirement
	send(t, conn, "MAIL FROM:<bob@example.org>")
	expect(t, read, "250")
}
