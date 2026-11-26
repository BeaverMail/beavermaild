package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// TestRFC7888LiteralPlus checks the LITERAL+, SASL-IR and UNSELECT audit (.specs/audit/rfc7888.md).
func TestRFC7888LiteralPlus(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	dial := func() (net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(c)
		expectPrefix(t, r, "* OK")
		return c, r
	}

	// 3: the example, non-synchronizing literals inside one command line.
	c, r := dial()
	defer c.Close()
	send(t, c, "l1 LOGIN {15+}\r\nalice@localhost {6+}\r\nbeaver")
	expectPrefix(t, r, "l1 OK")

	// RFC 3691 2: UNSELECT with no mailbox selected is BAD.
	send(t, c, "u1 UNSELECT")
	expectPrefix(t, r, "u1 BAD")
	send(t, c, "u2 EXAMINE INBOX")
	for line := ""; !strings.HasPrefix(line, "u2 OK"); {
		line, _ = r.ReadString('\n')
	}
	send(t, c, "u3 UNSELECT")
	expectPrefix(t, r, "u3 OK")

	// An octet count too long for an int is still a literal, too large: the client's bytes after it
	// are never read as commands (literal desync).
	send(t, c, "x1 NOOP {99999999999999999999+}\r\nx2 NOOP")
	expectPrefix(t, r, "* BYE [TOOBIG]")
	if line, err := r.ReadString('\n'); err == nil {
		t.Fatalf("after BYE: %q", line)
	}

	// The synchronizing form is refused before the continuation, so nothing is sent.
	c2, r2 := dial()
	defer c2.Close()
	send(t, c2, "y1 LOGIN {99999999999999999999}")
	expectPrefix(t, r2, "y1 BAD")
	send(t, c2, "y2 NOOP")
	expectPrefix(t, r2, "y2 OK")

	// RFC 4959 3: the initial response is base64 outside a quoted string or literal; a malformed
	// one is BAD, and "=" is the empty response.
	for i, ir := range []string{`"AGFsaWNlQGxvY2FsaG9zdABiZWF2ZXI="`, "=AAA", "AGFsaWNlQGxvY2FsaG9zdABiZWF2ZXI", "AGFsaWNlQGxvY2FsaG9zdABiZWF2ZXI=junk", "="} {
		tag := "s" + string(rune('0'+i))
		send(t, c2, tag+" AUTHENTICATE PLAIN "+ir)
		expectPrefix(t, r2, tag+" BAD")
	}
	send(t, c2, "s9 AUTHENTICATE PLAIN AGFsaWNlQGxvY2FsaG9zdABiZWF2ZXI=")
	expectPrefix(t, r2, "s9 OK")
}
