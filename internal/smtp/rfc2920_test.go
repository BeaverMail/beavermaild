package smtp_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// writeLog records every Write the server makes on its accepted connections.
type writeLog struct {
	mu     sync.Mutex
	writes []string
}

type loggingListener struct {
	net.Listener
	log *writeLog
}

func (l loggingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return loggingConn{c, l.log}, nil
}

type loggingConn struct {
	net.Conn
	log *writeLog
}

func (c loggingConn) Write(p []byte) (int, error) {
	c.log.mu.Lock()
	c.log.writes = append(c.log.writes, string(p))
	c.log.mu.Unlock()
	return c.Conn.Write(p)
}

// RFC 2920 3.2: replies to a pipelined group come in order; those to RSET, MAIL and RCPT go out in
// one write (2) while DATA's is not held (5); the text names the command (10); with no valid
// recipient DATA is refused (3).
func TestRFC2920PipelinedGroup(t *testing.T) {
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wl := &writeLog{}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, mail.NewInbox(store, blobs), nil, "", "", smtp.Options{})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeListener(sctx, loggingListener{ln, wl}) }()
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
	readEHLO(t, read, "PIPELINING")

	wl.mu.Lock()
	before := len(wl.writes)
	wl.mu.Unlock()
	if _, err := conn.Write([]byte("RSET\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<alice@localhost>\r\nRCPT TO:<ghost@localhost>\r\nDATA\r\n")); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"250 2.0.0", "250 2.1.0 Sender ok", "250 2.1.5 Recipient ok", "550", "354"} {
		expect(t, read, want)
	}
	wl.mu.Lock()
	writes := wl.writes[before:]
	wl.mu.Unlock()
	if len(writes) != 2 || strings.Count(writes[0], "\r\n") != 4 || !strings.HasPrefix(writes[1], "354") {
		t.Fatalf("group replies written as %q, want RSET..RCPT in one write, then 354", writes)
	}
	send(t, conn, "Subject: x\r\n\r\nbody\r\n.")
	expect(t, read, "250")

	if _, err := conn.Write([]byte("MAIL FROM:<sender@example.com>\r\nRCPT TO:<ghost@localhost>\r\nDATA\r\n")); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"250 2.1.0", "550", "503"} {
		expect(t, read, want)
	}
}
