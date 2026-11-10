package imap_test

import (
	"bufio"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestIMAPSyncAcrossSessions checks that commands other than FETCH/STORE/SEARCH report other
// sessions' changes before their tagged reply (RFC 3501 7.4.1), that the first session to see a new
// message takes its \Recent, and that a message expunged elsewhere does not drop the connection.
func TestIMAPSyncAcrossSessions(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	for i := range 2 { // distinct bodies: identical ones share a blob, which outlives one expunge
		if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\n\r\nsync "+strconv.Itoa(i)+"\r\n")); err != nil {
			t.Fatal(err)
		}
	}

	dial := func() (net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(c)
		expectPrefix(t, r, "* OK")
		send(t, c, "l1 LOGIN alice@localhost beaver")
		expectPrefix(t, r, "l1 OK")
		return c, r
	}
	// until returns the untagged lines before the reply tagged tag, and the tagged line.
	until := func(r *bufio.Reader, tag string) ([]string, string) {
		var lines []string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			line = strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(line, tag+" ") {
				return lines, line
			}
			lines = append(lines, line)
		}
	}
	a, ra := dial()
	b, rb := dial()
	send(t, a, "s1 SELECT INBOX")
	until(ra, "s1")
	send(t, b, "s1 SELECT INBOX")
	until(rb, "s1")

	// B appends: its own APPEND reports EXISTS, and B takes the new message's \Recent.
	msg := "From: c@d\r\n\r\nnew\r\n"
	send(t, b, "b1 APPEND INBOX {"+strconv.Itoa(len(msg))+"+}\r\n"+msg) // send adds the command's final CRLF
	lines, tagged := until(rb, "b1")
	if !strings.HasPrefix(tagged, "b1 OK") || !slices.Contains(lines, "* 3 EXISTS") || !slices.Contains(lines, "* 1 RECENT") {
		t.Fatalf("append: %q %q", lines, tagged)
	}
	send(t, a, "a1 NOOP")
	if lines, _ := until(ra, "a1"); !slices.Equal(lines, []string{"* 3 EXISTS"}) {
		t.Fatalf("noop after append: %q", lines)
	}
	send(t, a, "a2 FETCH 3 FLAGS")
	if lines, _ := until(ra, "a2"); len(lines) != 1 || strings.Contains(lines[0], `\Recent`) {
		t.Fatalf("\\Recent given to two sessions: %q", lines)
	}

	// B expunges message 1: A's FETCH and STORE must not report it, CHECK does.
	send(t, b, `b2 STORE 1 +FLAGS.SILENT (\Deleted)`)
	until(rb, "b2")
	send(t, b, "b3 EXPUNGE")
	until(rb, "b3")
	send(t, a, `a3 STORE 1 +FLAGS (\Flagged)`)
	if lines, tagged := until(ra, "a3"); len(lines) != 0 || !strings.HasPrefix(tagged, "a3 OK") {
		t.Fatalf("store on expunged message: %q %q", lines, tagged)
	}
	send(t, a, "a4 FETCH 1 BODY.PEEK[]")
	// RFC 2180 4.1: the body (still on disk until blob GC) or NO; never a dropped connection.
	if _, tagged := until(ra, "a4"); !strings.HasPrefix(tagged, "a4 OK") && !strings.HasPrefix(tagged, "a4 NO") {
		t.Fatalf("fetch of expunged message: %q", tagged)
	}
	send(t, a, "a5 CHECK")
	// Message 1 was \Recent for A, so the recent count drops too.
	if lines, _ := until(ra, "a5"); !slices.Equal(lines, []string{"* 1 EXPUNGE", "* 1 RECENT"}) {
		t.Fatalf("check after expunge: %q", lines)
	}
}
