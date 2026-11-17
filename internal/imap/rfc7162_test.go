package imap_test

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rfc7162Dial logs in as alice on a new connection to ln.
func rfc7162Dial(t *testing.T, ln net.Listener) (net.Conn, *bufio.Reader) {
	t.Helper()
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

// rfc7162Run sends "tag cmd" and returns the untagged lines and the tagged reply.
func rfc7162Run(t *testing.T, c net.Conn, r *bufio.Reader, tag, cmd string) ([]string, string) {
	t.Helper()
	send(t, c, tag+" "+cmd)
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

// RFC 7162 3.2, RFC 6851 4.4: MOVE raises the source mailbox's mod-sequence. Another session
// learns about the move at its next NOOP, and its stale view cannot change the moved message in
// its new mailbox (RFC 2180 4.2): STORE skips it, MOVE fails.
func TestRFC7162MoveSeenByOtherSession(t *testing.T) {
	t.Parallel()
	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	for i := range 3 {
		if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\n\r\nmove "+strconv.Itoa(i)+"\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	a, ra := rfc7162Dial(t, ln)
	b, rb := rfc7162Dial(t, ln)
	rfc7162Run(t, a, ra, "a1", "SELECT INBOX (CONDSTORE)")
	rfc7162Run(t, b, rb, "b1", "SELECT INBOX (CONDSTORE)")

	// Before a syncs, its view still holds message 1: STORE must not reach it in Trash, and MOVE
	// fails (the reply then reports the expunge: MOVE syncs before its tagged reply).
	_, tagged := rfc7162Run(t, b, rb, "b2", "MOVE 1 Trash")
	if !strings.HasPrefix(tagged, "b2 OK [HIGHESTMODSEQ ") {
		t.Fatalf("MOVE reply %q, want HIGHESTMODSEQ (RFC 6851 4.4)", tagged)
	}
	lines, _ := rfc7162Run(t, a, ra, "a3", `STORE 1 +FLAGS (\Flagged)`)
	if len(lines) != 0 {
		t.Fatalf("STORE on a moved message answered %q", lines)
	}
	lines, tagged = rfc7162Run(t, a, ra, "a4", "MOVE 1 Trash")
	if !strings.HasPrefix(tagged, "a4 NO") || !strings.Contains(strings.Join(lines, "\n"), "* 1 EXPUNGE") {
		t.Fatalf("MOVE of a message already moved: %q %q", lines, tagged)
	}
	// The plain case: the next NOOP reports another session's MOVE.
	rfc7162Run(t, b, rb, "b3", "MOVE 1 Trash")
	lines, _ = rfc7162Run(t, a, ra, "a5", "NOOP")
	if !strings.Contains(strings.Join(lines, "\n"), "* 1 EXPUNGE") {
		t.Fatalf("NOOP after another session's MOVE: %q", lines)
	}
	rfc7162Run(t, a, ra, "a6", "SELECT Trash")
	lines, _ = rfc7162Run(t, a, ra, "a7", "FETCH 1:* (FLAGS)")
	if len(lines) != 2 || strings.Contains(strings.Join(lines, "\n"), `\Flagged`) {
		t.Fatalf("moved messages %q", lines)
	}
}

// RFC 7162 7: HIGHESTMODSEQ in a response code is a mod-sequence-value (at least 1), and 0 in
// STATUS means NOMODSEQ: an untouched mailbox reports 1, and its first message is newer.
func TestRFC7162EmptyMailboxHighestModSeq(t *testing.T) {
	t.Parallel()
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	a, ra := rfc7162Dial(t, ln)
	rfc7162Run(t, a, ra, "a1", "CREATE Empty")
	lines, _ := rfc7162Run(t, a, ra, "a2", "STATUS Empty (HIGHESTMODSEQ)")
	if len(lines) != 1 || !strings.HasSuffix(lines[0], "(HIGHESTMODSEQ 1)") {
		t.Fatalf("STATUS %q", lines)
	}
	lines, _ = rfc7162Run(t, a, ra, "a3", "SELECT Empty (CONDSTORE)")
	if !strings.Contains(strings.Join(lines, "\n"), "* OK [HIGHESTMODSEQ 1]") {
		t.Fatalf("SELECT %q", lines)
	}
	rfc7162Run(t, a, ra, "a4", "UNSELECT")
	send(t, a, "a5 APPEND Empty {10}")
	expectPrefix(t, ra, "+")
	send(t, a, "Subject: x")
	rfc7162Run(t, a, ra, "a6", "NOOP")
	lines, _ = rfc7162Run(t, a, ra, "a7", "STATUS Empty (HIGHESTMODSEQ)")
	if len(lines) != 1 || strings.HasSuffix(lines[0], "(HIGHESTMODSEQ 1)") {
		t.Fatalf("STATUS after APPEND %q: still 1", lines)
	}
}

// RFC 5161 3.1: unknown names are ignored; ENABLED lists only what the command enabled.
func TestRFC5161EnableUnknown(t *testing.T) {
	t.Parallel()
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	a, ra := rfc7162Dial(t, ln)
	for _, st := range []struct{ cmd, enabled string }{
		{"ENABLE X-UNKNOWN", "* ENABLED"},
		{"ENABLE CONDSTORE X-UNKNOWN", "* ENABLED CONDSTORE"},
		{"ENABLE CONDSTORE QRESYNC", "* ENABLED QRESYNC"},
	} {
		lines, tagged := rfc7162Run(t, a, ra, "e", st.cmd)
		if len(lines) != 1 || lines[0] != st.enabled || !strings.HasPrefix(tagged, "e OK") {
			t.Fatalf("%s: %q %q, want %q", st.cmd, lines, tagged, st.enabled)
		}
	}
	if _, tagged := rfc7162Run(t, a, ra, "e", "ENABLE"); !strings.HasPrefix(tagged, "e BAD") {
		t.Fatalf("ENABLE without arguments: %q", tagged)
	}
}

// RFC 7162 3.2.7, 3.2.9: with QRESYNC, EXPUNGE and UID EXPUNGE that remove a message carry the new
// HIGHESTMODSEQ in their tagged OK; 3.2.8: CLOSE does not. 3.2.10.2: no VANISHED during UID SEARCH
// (whose criteria may hold message numbers); the next NOOP reports it.
func TestRFC7162ExpungeHighestModSeq(t *testing.T) {
	t.Parallel()
	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	for i := range 4 {
		if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\n\r\nexp "+strconv.Itoa(i)+"\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	a, ra := rfc7162Dial(t, ln)
	b, rb := rfc7162Dial(t, ln)
	rfc7162Run(t, a, ra, "a0", "ENABLE QRESYNC")
	rfc7162Run(t, a, ra, "a1", "SELECT INBOX")
	rfc7162Run(t, a, ra, "a2", `STORE 1:2 +FLAGS.SILENT (\Deleted)`)
	lines, tagged := rfc7162Run(t, a, ra, "a3", "EXPUNGE")
	if len(lines) != 2 || lines[0] != "* VANISHED 1" || !strings.HasPrefix(tagged, "a3 OK [HIGHESTMODSEQ ") {
		t.Fatalf("EXPUNGE %q %q", lines, tagged)
	}
	if _, tagged = rfc7162Run(t, a, ra, "a4", "UID EXPUNGE 1:*"); tagged != "a4 OK UID EXPUNGE completed" {
		t.Fatalf("UID EXPUNGE removing nothing %q", tagged)
	}

	rfc7162Run(t, b, rb, "b1", "SELECT INBOX")
	rfc7162Run(t, b, rb, "b2", `STORE 1 +FLAGS.SILENT (\Deleted)`)
	rfc7162Run(t, b, rb, "b3", "EXPUNGE")
	if lines, _ = rfc7162Run(t, a, ra, "a5", "UID SEARCH 1"); strings.Contains(strings.Join(lines, "\n"), "VANISHED") {
		t.Fatalf("VANISHED during UID SEARCH: %q", lines)
	}
	if lines, _ = rfc7162Run(t, a, ra, "a6", "NOOP"); !strings.Contains(strings.Join(lines, "\n"), "* VANISHED 3") {
		t.Fatalf("NOOP %q", lines)
	}

	rfc7162Run(t, a, ra, "a7", `STORE 1 +FLAGS.SILENT (\Deleted)`)
	if _, tagged = rfc7162Run(t, a, ra, "a8", "CLOSE"); tagged != "a8 OK CLOSE completed" {
		t.Fatalf("CLOSE %q", tagged)
	}
}
