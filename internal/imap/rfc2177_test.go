package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// RFC 2177: IDLE works in the authenticated state (4) and a DONE that arrives in pieces across the
// poll still ends it (3). RFC 2180: STORE naming only expunged messages is NO (4.2.2), a mixture
// stays OK (4.2.3); a selected mailbox deleted by another session ends with BYE (3.3).
func TestRFC2177Idle(t *testing.T) {
	t.Parallel()
	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	for i := 1; i <= 4; i++ {
		if _, err := inbox.Deliver(ctx, accID, []byte(fmt.Sprintf("From: a@example.org\r\nSubject: m%d\r\n\r\nbody\r\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	a, ra := rfc7162Dial(t, ln)
	b, rb := rfc7162Dial(t, ln)

	send(t, a, "i1 IDLE")
	expectPrefix(t, ra, "+ ")
	send(t, a, "DONE")
	expectPrefix(t, ra, "i1 OK")

	rfc7162Run(t, a, ra, "s1", "SELECT INBOX")
	send(t, a, "i2 IDLE")
	expectPrefix(t, ra, "+ ")
	fmt.Fprint(a, "DO")
	time.Sleep(1200 * time.Millisecond) // past two polls
	fmt.Fprint(a, "NE\r\n")
	expectPrefix(t, ra, "i2 OK")

	rfc7162Run(t, b, rb, "b1", "SELECT INBOX")
	rfc7162Run(t, b, rb, "b2", `STORE 3:4 +FLAGS.SILENT (\Deleted)`)
	rfc7162Run(t, b, rb, "b3", "EXPUNGE")
	if _, tagged := rfc7162Run(t, a, ra, "t1", `STORE 3:4 +FLAGS (\Seen)`); !strings.HasPrefix(tagged, "t1 NO [EXPUNGEISSUED]") {
		t.Fatalf("STORE on expunged only: %q", tagged)
	}
	if _, tagged := rfc7162Run(t, a, ra, "t2", `STORE 3:4 +FLAGS.SILENT (\Seen)`); !strings.HasPrefix(tagged, "t2 OK") {
		t.Fatalf("STORE.SILENT on expunged only: %q", tagged)
	}
	if lines, tagged := rfc7162Run(t, a, ra, "t3", `STORE 2:4 +FLAGS (\Seen)`); len(lines) != 1 || !strings.HasPrefix(tagged, "t3 OK") {
		t.Fatalf("STORE on a mixture: %q %q", lines, tagged)
	}

	rfc7162Run(t, b, rb, "b4", "CREATE Foo")
	rfc7162Run(t, a, ra, "s2", "SELECT Foo")
	rfc7162Run(t, b, rb, "b5", "DELETE Foo")
	send(t, a, "n1 NOOP")
	expectPrefix(t, ra, "* BYE")
}
