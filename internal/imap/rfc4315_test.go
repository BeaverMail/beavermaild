package imap_test

import (
	"fmt"
	"strings"
	"testing"
)

// RFC 4315 3 / RFC 6851 4.3: COPYUID pairs each source UID with its copy, whatever order the set
// names them in. 2.1: UID EXPUNGE takes every \Deleted message in the set, one this session had not
// seen yet included. RFC 9208: COPY over quota is a tagged NO [OVERQUOTA], not a dropped session.
func TestRFC4315UIDPlus(t *testing.T) {
	t.Parallel()
	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	for i := 1; i <= 6; i++ {
		if _, err := inbox.Deliver(ctx, accID, []byte(fmt.Sprintf("From: a@example.org\r\nSubject: m%d\r\n\r\nbody\r\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	a, ra := rfc7162Dial(t, ln)
	b, rb := rfc7162Dial(t, ln)
	rfc7162Run(t, a, ra, "a0", "CREATE Dst")
	rfc7162Run(t, a, ra, "a1", "SELECT INBOX")

	// Copy 3 then 1: Dst UID 1 is m1 and UID 2 is m3, and COPYUID must say so.
	if _, tagged := rfc7162Run(t, a, ra, "a2", "COPY 3,1 Dst"); !strings.Contains(tagged, " 1,3 1:2]") {
		t.Fatalf("COPY 3,1: %q", tagged)
	}
	if lines, tagged := rfc7162Run(t, a, ra, "a3", "MOVE 6,4 Dst"); !strings.Contains(strings.Join(lines, "\n"), " 4,6 3:4]") {
		t.Fatalf("MOVE 6,4: %q %q", lines, tagged)
	}
	rfc7162Run(t, b, rb, "b0", "SELECT Dst")
	lines, _ := rfc7162Run(t, b, rb, "b1", "UID FETCH 1:4 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
	got := strings.Join(lines, "\n")
	for _, want := range []string{"m1", "m3", "m4", "m6"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Dst:\n%s", got)
		}
	}
	if strings.Index(got, "m1") > strings.Index(got, "m3") || strings.Index(got, "m4") > strings.Index(got, "m6") {
		t.Fatalf("copies out of source order, COPYUID pairs them wrongly:\n%s", got)
	}

	rfc7162Run(t, b, rb, "b2", "SELECT INBOX")
	rfc7162Run(t, b, rb, "b3", "APPEND INBOX (\\Deleted) {20}\r\nFrom: x@example.org")
	lines, _ = rfc7162Run(t, a, ra, "a4", "UID EXPUNGE 1:1000")
	if !strings.Contains(strings.Join(lines, "\n"), "EXPUNGE") {
		t.Fatalf("UID EXPUNGE left the new \\Deleted message: %q", lines)
	}

	// RFC 3501 6.3.2: EXAMINE protects the selected mailbox only; COPY from it is allowed, MOVE is not.
	rfc7162Run(t, a, ra, "e0", "EXAMINE INBOX")
	if _, tagged := rfc7162Run(t, a, ra, "e1", "COPY 1 Dst"); !strings.HasPrefix(tagged, "e1 OK [COPYUID") {
		t.Fatalf("COPY from EXAMINE: %q", tagged)
	}
	if _, tagged := rfc7162Run(t, a, ra, "e2", "MOVE 1 Dst"); !strings.HasPrefix(tagged, "e2 NO") {
		t.Fatalf("MOVE from EXAMINE: %q", tagged)
	}

	one := uint64(1)
	if err := inbox.SetQuotaLimits(ctx, accID, &one, nil); err != nil {
		t.Fatal(err)
	}
	if _, tagged := rfc7162Run(t, a, ra, "a5", "COPY 1 Dst"); !strings.HasPrefix(tagged, "a5 NO [OVERQUOTA]") {
		t.Fatalf("COPY over quota: %q", tagged)
	}
	if _, tagged := rfc7162Run(t, a, ra, "a6", "NOOP"); !strings.HasPrefix(tagged, "a6 OK") {
		t.Fatalf("session after OVERQUOTA: %q", tagged)
	}
}

// RFC 2180 4.4.1 / RFC 5530 3: COPY or MOVE of a message another session expunged copies nothing
// and says why with EXPUNGEISSUED, so the client NOOPs instead of failing.
func TestCopyExpungedByOtherSession(t *testing.T) {
	t.Parallel()
	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	for i := 1; i <= 2; i++ {
		if _, err := inbox.Deliver(ctx, accID, []byte(fmt.Sprintf("From: a@example.org\r\nSubject: m%d\r\n\r\nbody\r\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	a, ra := rfc7162Dial(t, ln)
	b, rb := rfc7162Dial(t, ln)
	rfc7162Run(t, a, ra, "a0", "CREATE Dst")
	rfc7162Run(t, a, ra, "a1", "SELECT INBOX")
	rfc7162Run(t, b, rb, "b0", "SELECT INBOX")
	// The NO itself carries the EXPUNGE, so B expunges the next message before MOVE.
	for _, cmd := range []string{"COPY", "MOVE"} {
		rfc7162Run(t, b, rb, "b1", "STORE 1 +FLAGS (\\Deleted)")
		rfc7162Run(t, b, rb, "b2", "EXPUNGE")
		if _, tagged := rfc7162Run(t, a, ra, "a2", cmd+" 1 Dst"); !strings.HasPrefix(tagged, "a2 NO [EXPUNGEISSUED]") {
			t.Fatalf("%s of expunged message: %q", cmd, tagged)
		}
	}
	if lines, _ := rfc7162Run(t, b, rb, "b3", "STATUS Dst (MESSAGES)"); !strings.Contains(strings.Join(lines, "\n"), "MESSAGES 0") {
		t.Fatalf("partial copy: %q", lines)
	}
}
