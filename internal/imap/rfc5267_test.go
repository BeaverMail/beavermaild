package imap_test

import (
	"strconv"
	"strings"
	"testing"
)

// RFC 5267 4.3 (RFC 3501 errata): message numbers in an updating search mean the messages they
// named when the command arrived, so an expunge that renumbers the mailbox adds nothing; a UID
// "n:*" still takes new messages. RFC 5465 7: UPDATE (fetch-att) sends EXISTS, the new message's
// FETCH, then ADDTO, and no FETCH for a message joining through a flag change. RFC 5267 5:
// CANCELUPDATE needs a selected mailbox.
func TestRFC5267UpdatingContexts(t *testing.T) {
	t.Parallel()
	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	deliver := func(i int) {
		t.Helper()
		if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\nSubject: s"+strconv.Itoa(i)+"\r\n\r\nx\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 4 {
		deliver(i)
	}
	a, ra := rfc7162Dial(t, ln)
	b, rb := rfc7162Dial(t, ln)
	if _, tagged := rfc7162Run(t, a, ra, "c0", `CANCELUPDATE "x"`); !strings.HasPrefix(tagged, "c0 NO") {
		t.Fatalf("CANCELUPDATE without a mailbox: %q", tagged)
	}
	rfc7162Run(t, a, ra, "a1", "SELECT INBOX")
	rfc7162Run(t, b, rb, "b1", "SELECT INBOX")
	rfc7162Run(t, a, ra, "s1", "SEARCH RETURN (UPDATE) 1:2")
	rfc7162Run(t, a, ra, "s2", "UID SEARCH RETURN (UPDATE) UID 3:*")
	rfc7162Run(t, a, ra, "s3", "UID SEARCH RETURN (UPDATE (FLAGS)) UNFLAGGED")

	rfc7162Run(t, b, rb, "b2", `STORE 1 +FLAGS.SILENT (\Deleted)`)
	rfc7162Run(t, b, rb, "b3", "EXPUNGE")
	deliver(9)
	lines, _ := rfc7162Run(t, a, ra, "a2", "NOOP")
	got := strings.Join(lines, "\n")
	for _, bad := range []string{`(TAG "s1") ADDTO`} {
		if strings.Contains(got, bad) {
			t.Fatalf("renumbering changed a message-number context:\n%s", got)
		}
	}
	want := []string{`* ESEARCH (TAG "s1") REMOVEFROM (0 1)`, "* 1 EXPUNGE", "* 4 EXISTS",
		"* 4 FETCH (UID 5 FLAGS (", `* ESEARCH (TAG "s3") UID ADDTO (0 5)`}
	pos := -1
	for _, w := range want {
		i := strings.Index(got, w)
		if i <= pos {
			t.Fatalf("want %q after the previous ones:\n%s", w, got)
		}
		pos = i
	}
	if !strings.Contains(got, `* ESEARCH (TAG "s2") UID ADDTO (0 5)`) {
		t.Fatalf("UID 3:* did not take the new message:\n%s", got)
	}

	// A message joining through a flag change: ADDTO without FETCH.
	rfc7162Run(t, b, rb, "b3n", "NOOP") // b sees the new message
	rfc7162Run(t, b, rb, "b4", `UID STORE 5 +FLAGS.SILENT (\Flagged)`)
	rfc7162Run(t, a, ra, "a3", "NOOP")
	rfc7162Run(t, b, rb, "b5", `UID STORE 5 -FLAGS.SILENT (\Flagged)`)
	lines, _ = rfc7162Run(t, a, ra, "a4", "NOOP")
	got = strings.Join(lines, "\n")
	if !strings.Contains(got, `(TAG "s3") UID ADDTO`) || strings.Count(got, "FETCH") != 1 {
		t.Fatalf("flag change: want the flag FETCH and an ADDTO, no extra FETCH:\n%s", got)
	}
}
