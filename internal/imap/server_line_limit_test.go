package imap_test

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// TestIMAPLineLimit checks that a long command line within the limit works and that a line
// without end is cut off at the limit instead of being buffered.
func TestIMAPLineLimit(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	expectPrefix(t, r, "* OK")

	send(t, c, `i1 ID ("x" "`+strings.Repeat("a", 60<<10)+`")`)
	expectPrefix(t, r, "* ID")
	expectPrefix(t, r, "i1 OK")

	// 1 MiB with no newline: the server must hang up once past the limit.
	go func() { _, _ = c.Write([]byte(strings.Repeat("a", 1<<20))) }()
	if _, err := io.ReadAll(r); err != nil && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("connection not closed: %v", err)
	}
}

// TestIMAPLiteralTooBig checks oversized literals (RFC 7888 4): a synchronizing one is refused
// before upload and the session goes on; a non-synchronizing one, already on its way, ends the
// connection with BYE [TOOBIG] instead of being read as commands.
func TestIMAPLiteralTooBig(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	dial := func() (net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(c)
		expectPrefix(t, r, "* OK")
		send(t, c, "l1 LOGIN alice@localhost beaver")
		expectPrefix(t, r, "l1 OK")
		return c, r
	}
	tooBig := strconv.Itoa(mail.MaxAppendBytes + 1)

	c, r := dial()
	send(t, c, "a1 APPEND INBOX {"+tooBig+"}")
	expectPrefix(t, r, "a1 NO [TOOBIG]")
	send(t, c, "a2 NOOP")
	expectPrefix(t, r, "a2 OK")

	for _, cmd := range []string{"a3 APPEND INBOX {" + tooBig + "+}", "a4 SEARCH TEXT {70000+}"} {
		c, r := dial()
		send(t, c, cmd)
		go func() { _, _ = c.Write([]byte(strings.Repeat("a", 1<<20))) }()
		expectPrefix(t, r, "* BYE [TOOBIG]")
		if _, err := io.ReadAll(r); err != nil && !strings.Contains(err.Error(), "reset") {
			t.Fatalf("%s: connection not closed: %v", cmd, err)
		}
	}
}
