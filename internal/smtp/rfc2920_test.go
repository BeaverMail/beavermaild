package smtp_test

import (
	"bufio"
	"context"
	"errors"
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
	send(t, conn, "From: sender@example.com\r\nSubject: x\r\n\r\nbody\r\n.")
	expect(t, read, "250")

	if _, err := conn.Write([]byte("MAIL FROM:<sender@example.com>\r\nRCPT TO:<ghost@localhost>\r\nDATA\r\n")); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"250 2.1.0", "550", "503"} {
		expect(t, read, want)
	}
}

// startPipeServer serves port 25 SMTP with the given read (and write) timeout and returns a client
// that has sent EHLO.
func startPipeServer(t *testing.T, timeout time.Duration) (net.Conn, *bufio.Reader) {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs")), nil, "", "", smtp.Options{ReadTimeout: timeout})
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = srv.ServeListener(sctx, smallSendListener{ln}) }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO test")
	readEHLO(t, read, "PIPELINING")
	return conn, read
}

// smallSendListener gives each accepted conn a small kernel send buffer, so the server blocks in
// Write after a few KiB of replies a client does not read (loopback buffers grow to MiBs).
type smallSendListener struct{ net.Listener }

func (l smallSendListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetWriteBuffer(4096)
	}
	return c, err
}

// floodRSET pipelines RSET commands without reading the replies until max octets are sent or the
// server stops reading, and returns the complete commands sent. With midLine every TCP segment
// ends in the middle of a line, so the server's input buffer never runs empty.
func floodRSET(conn net.Conn, max int, stall time.Duration, midLine bool) int {
	sent, lead, seg := 0, 0, []byte(strings.Repeat("RSET\r\n", 8192))
	if midLine {
		lead, _ = conn.Write([]byte("RS"))
		seg = []byte(strings.Repeat("ET\r\nRS", 8192))
	}
	for sent < max {
		_ = conn.SetWriteDeadline(time.Now().Add(stall))
		n, err := conn.Write(seg)
		sent += n
		if err != nil {
			break
		}
	}
	_ = conn.SetWriteDeadline(time.Time{})
	if midLine {
		return (lead + sent - 2) / 6
	}
	return sent / 6
}

// RFC 2920 3.2 (2), (7): a pipelined group that never ends (each segment cut mid-line) must not be
// read ahead without limit. Before, the server read the whole group into memory before running
// it: 200 MiB of NOOPs grew the heap to 2.6 GiB. Now it runs each command as it reads it and its
// held replies are bounded, so a client that does not read them is soon stopped by TCP.
// Not parallel: a server slowed by other tests would stall the client for a reason of its own.
func TestRFC2920PipelineFloodBounded(t *testing.T) {
	conn, _ := startPipeServer(t, time.Minute)
	const max = 64 << 20
	if cmds := floodRSET(conn, max, 3*time.Second, true); cmds*6 >= max/2 {
		t.Fatalf("server read %d MiB of a group whose replies are never read, want it stopped by TCP", cmds*6>>20)
	}
}

// A client that pipelines commands and never reads the replies is cut off by the write deadline
// (smtp.read_timeout bounds writes too, as Postfix's smtpd_timeout): before, the session stayed
// blocked in Write forever.
func TestPipelinedClientNotReadingIsCutOff(t *testing.T) {
	t.Parallel()
	conn, read := startPipeServer(t, time.Second)
	// Small client buffers too: the server blocks in Write after a few KiB of replies, so it has
	// long been blocked when the client starts reading (also under -race).
	tc := conn.(*net.TCPConn)
	_ = tc.SetReadBuffer(4096)
	_ = tc.SetWriteBuffer(4096)
	cmds := floodRSET(conn, 64<<20, time.Second, false)
	time.Sleep(3 * time.Second) // past the server's write deadline
	// The server must have closed the connection: the client reads what was already in flight,
	// then EOF or a reset. A client deadline instead means the session was still alive.
	replies := 0
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	for {
		line, err := read.ReadString('\n')
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("session still open after %d replies to %d commands: never cut off", replies, cmds)
			}
			break
		}
		if strings.HasPrefix(line, "250 ") {
			replies++
		}
	}
	if replies >= cmds {
		t.Fatalf("got %d replies to %d commands: the stalled session was never cut off", replies, cmds)
	}
}

// RFC 2920 3.2 (7): held replies go out when the input runs out, even if a partial line is
// buffered. Before, the server waited for the rest of the line holding the replies.
func TestRFC2920FlushBeforePartialLine(t *testing.T) {
	t.Parallel()
	conn, read := startPipeServer(t, time.Minute)
	if _, err := conn.Write([]byte("RSET\r\nRSET\r\nRS")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	expect(t, read, "250")
	expect(t, read, "250")
}
