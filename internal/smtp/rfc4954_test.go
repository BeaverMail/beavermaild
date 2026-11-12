package smtp_test

import (
	"bufio"
	"context"
	"encoding/base64"
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
	"github.com/BeaverMail/beavermaild/internal/tlsload"
	"github.com/BeaverMail/beavermaild/internal/tlsload/tlstest"
)

// submissionTLS starts a submission server on implicit TLS and returns a client after EHLO.
func submissionTLS(t *testing.T) (net.Conn, *bufio.Reader) {
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
	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"localhost"})
	certs, err := tlsload.Load(certFile, keyFile, "1.2")
	if err != nil {
		t.Fatal(err)
	}
	blobs := blob.NewFS(t.TempDir() + "/blobs")
	tlsLn, err := certs.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, mail.NewInbox(store, blobs), mail.NewQueue(store, blobs), "", "", smtp.Options{Certs: certs})
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = srv.ServeSubmissionListener(sctx, tlsLn, true) }()
	time.Sleep(20 * time.Millisecond)
	conn, err := tlsload.DialTestClient(tlsLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO test")
	readEHLO(t, read, "AUTH PLAIN")
	return conn, read
}

// RFC 4954 4 and RFC 4616 2: BASE64 only ("=" is empty), "*" cancels with 501, PLAIN has three
// fields and its authzid cannot name someone else, LOGIN takes no initial response, a line past
// the authentication buffer fails the command (500 5.5.6) and not the session, no AUTH inside a
// transaction or after a successful one (503). RFC 4954 5: MAIL FROM takes AUTH=.
func TestRFC4954AuthExchange(t *testing.T) {
	t.Parallel()
	conn, read := submissionTLS(t)
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	good := b64("\x00alice@localhost\x00" + directory.SeedPassword())
	steps := []struct{ send, want string }{
		{"AUTH CRAM-MD5", "504 5.5.4"},
		{"AUTH PLAIN !!!notbase64", "501 5.5.2"},
		{"AUTH PLAIN AAA=BBB", "501 5.5.2"},
		{"AUTH PLAIN =", "535"},
		{"AUTH PLAIN " + b64("alice@localhost\x00"+directory.SeedPassword()), "535"}, // two fields
		{"AUTH PLAIN " + b64("bob@localhost\x00alice@localhost\x00"+directory.SeedPassword()), "535"},
		{"AUTH PLAIN", "334"},
		{"*", "501"},
		{"AUTH LOGIN", "334"},
		{"*", "501"}, // cancelled at the user name: the next command is a command again
		{"AUTH LOGIN " + b64("alice@localhost"), "501"},
		{"AUTH PLAIN", "334"},
		{strings.Repeat("A", 20000), "500 5.5.6"},
		{"NOOP", "250"},                              // the session survives
		{"MAIL FROM:<x@example.org> AUTH=<>", "530"}, // AUTH= accepted; MAIL still needs a login
		{"MAIL FROM:<x@example.org> AUTH=bad=value", "501"},
		{"AUTH PLAIN " + good, "235"},
		{"AUTH PLAIN " + good, "503"},
		{"MAIL FROM:<alice@localhost> AUTH=alice+40localhost", "250"},
	}
	for _, st := range steps {
		send(t, conn, st.send)
		expect(t, read, st.want)
	}
}

// RFC 4954 4: an AUTH inside a mail transaction is refused, and the transaction is kept.
func TestRFC4954NoAuthInTransaction(t *testing.T) {
	t.Parallel()
	conn, read := submissionTLS(t)
	good := base64.StdEncoding.EncodeToString([]byte("\x00alice@localhost\x00" + directory.SeedPassword()))
	send(t, conn, "AUTH PLAIN "+good)
	expect(t, read, "235")
	send(t, conn, "MAIL FROM:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "AUTH PLAIN "+good)
	expect(t, read, "503")
	send(t, conn, "RCPT TO:<bob@example.com>")
	expect(t, read, "250")
}
