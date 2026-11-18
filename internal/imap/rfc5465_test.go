package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// rfc5465Events reads what the server pushes on an idle NOTIFY connection for a little longer than
// one poll interval.
func rfc5465Events(t *testing.T, c net.Conn, r *bufio.Reader) []string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	defer c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return lines
		}
		lines = append(lines, strings.TrimRight(line, "\r\n"))
	}
}

// RFC 5465 5.4: a created or deleted mailbox's direct parent is reported too; a rename is one
// event for the renamed mailbox, none for its children. 8: a MessageNew fetch-att list is only
// allowed with SELECTED/SELECTED-DELAYED.
func TestRFC5465MailboxName(t *testing.T) {
	t.Parallel()
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	a, ra := rfc7162Dial(t, ln)
	b, rb := rfc7162Dial(t, ln)
	if _, tagged := rfc7162Run(t, a, ra, "a0", "NOTIFY SET (personal (MessageNew (UID) MessageExpunge))"); !strings.HasPrefix(tagged, "a0 BAD") {
		t.Fatalf("fetch-att outside SELECTED: %q", tagged)
	}
	rfc7162Run(t, b, rb, "b0", "CREATE Top/Old")
	rfc7162Run(t, a, ra, "a1", "NOTIFY SET (personal (MailboxName))")

	rfc7162Run(t, b, rb, "b1", "RENAME Top New")
	got := strings.Join(rfc5465Events(t, a, ra), "\n")
	if !strings.Contains(got, `"New" ("OLDNAME" ("Top"))`) || strings.Contains(got, "New/Old") {
		t.Fatalf("after RENAME Top New:\n%s", got)
	}

	rfc7162Run(t, b, rb, "b2", "DELETE New/Old")
	got = strings.Join(rfc5465Events(t, a, ra), "\n")
	if !strings.Contains(got, `LIST (\NonExistent) "/" "New/Old"`) || !strings.Contains(got, `LIST (\HasNoChildren) "/" "New"`) {
		t.Fatalf("after DELETE New/Old, want the mailbox and its parent:\n%s", got)
	}

	rfc7162Run(t, b, rb, "b3", "CREATE New/Kid")
	got = strings.Join(rfc5465Events(t, a, ra), "\n")
	if !strings.Contains(got, `"New/Kid"`) || !strings.Contains(got, `LIST (\HasChildren) "/" "New"`) {
		t.Fatalf("after CREATE New/Kid, want the mailbox and its parent:\n%s", got)
	}
}
