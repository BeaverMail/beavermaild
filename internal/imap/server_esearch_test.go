package imap_test

import (
	"bufio"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestIMAPESearchESortID checks SEARCH/SORT RETURN (RFC 4731, RFC 5267) and ID (RFC 2971).
func TestIMAPESearchESortID(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	for i := range 4 {
		if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\n\r\nesearch "+strings.Repeat("x", i)+"\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	until := func(tag string) ([]string, string) {
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
	check := func(cmd string, want ...string) {
		t.Helper()
		tag, _, _ := strings.Cut(cmd, " ")
		send(t, c, cmd)
		lines, tagged := until(tag)
		if !strings.HasPrefix(tagged, tag+" OK") || !slices.Equal(lines, want) {
			t.Fatalf("%s: %q %q, want %q", cmd, lines, tagged, want)
		}
	}
	expectPrefix(t, r, "* OK")
	check("i1 ID NIL", `* ID ("name" "BeaverMail")`) // before login too
	send(t, c, "l1 LOGIN alice@localhost beaver")
	until("l1")
	send(t, c, "s1 SELECT INBOX")
	until("s1")

	check("e1 SEARCH RETURN (MIN MAX COUNT) ALL", `* ESEARCH (TAG "e1") MIN 1 MAX 4 COUNT 4`)
	send(t, c, `x1 STORE 2 +FLAGS.SILENT (\Deleted)`)
	until("x1")
	send(t, c, "x2 EXPUNGE")
	until("x2")
	check("e2 UID SEARCH RETURN () ALL", `* ESEARCH (TAG "e2") UID ALL 1,3:4`)
	check("e3 SEARCH RETURN (MIN COUNT) 100", `* ESEARCH (TAG "e3") COUNT 0`)
	check("e4 SORT RETURN (ALL MIN) (REVERSE SIZE) US-ASCII ALL", `* ESEARCH (TAG "e4") MIN 3 ALL 3,2,1`)
	send(t, c, "e5 SEARCH RETURN (SAVE) ALL")
	if _, tagged := until("e5"); !strings.HasPrefix(tagged, "e5 BAD") {
		t.Fatalf("unsupported RETURN option: %q", tagged)
	}
	check("e6 SEARCH ALL", "* SEARCH 1 2 3") // plain SEARCH unchanged

	// UIDBATCHES: one batch holds the whole mailbox, newest UID first.
	check("b1 UIDBATCHES 500", `* UIDBATCHES (TAG "b1") 4:1`)
	check("b2 UIDBATCHES 500 2:3", `* UIDBATCHES (TAG "b2")`)
	send(t, c, "b3 UIDBATCHES 499")
	if _, tagged := until("b3"); tagged != "b3 NO [TOOFEW] minimum batch size is 500" {
		t.Fatal(tagged)
	}
	send(t, c, "b4 UIDBATCHES 500 4:1")
	if _, tagged := until("b4"); !strings.HasPrefix(tagged, "b4 BAD") {
		t.Fatal(tagged)
	}

	// CONTEXT (RFC 5267): PARTIAL ranges in result order, UPDATE contexts, CANCELUPDATE.
	check("p1 SORT RETURN (PARTIAL 3:2) (REVERSE SIZE) US-ASCII ALL", `* ESEARCH (TAG "p1") PARTIAL (2:3 2,1)`)
	check("p2 SEARCH RETURN (PARTIAL 4:9) ALL", `* ESEARCH (TAG "p2") PARTIAL (4:9 NIL)`)
	for _, bad := range []string{"p3 SEARCH RETURN (PARTIAL 1:*) ALL", "p4 SEARCH RETURN (PARTIAL 1:2 ALL) ALL"} {
		send(t, c, bad)
		if tag, _, _ := strings.Cut(bad, " "); !strings.HasPrefix(func() string { _, l := until(tag); return l }(), tag+" BAD") {
			t.Fatal(bad)
		}
	}
	has := func(cmd, want string) {
		t.Helper()
		tag, _, _ := strings.Cut(cmd, " ")
		send(t, c, cmd)
		if lines, _ := until(tag); !slices.Contains(lines, want) {
			t.Fatalf("%s: %q, want %q", cmd, lines, want)
		}
	}
	check("u1 SEARCH RETURN (UPDATE) SEEN", `* ESEARCH (TAG "u1")`)
	check("u2 UID SORT RETURN (UPDATE ALL) (REVERSE SIZE) US-ASCII UNSEEN", `* ESEARCH (TAG "u2") UID ALL 4,3,1`)
	send(t, c, "u1 SEARCH RETURN (UPDATE) ALL")
	if _, tagged := until("u1"); !strings.HasPrefix(tagged, "u1 BAD") {
		t.Fatal("reused context tag:", tagged)
	}
	has(`s1 STORE 1,3 +FLAGS (\Seen)`, `* ESEARCH (TAG "u1") ADDTO (0 1,3)`)
	has(`s2 STORE 3 -FLAGS (\Seen)`, `* ESEARCH (TAG "u2") UID ADDTO (1 4)`)
	has(`s3 STORE 2 +FLAGS (\Seen \Deleted)`, `* ESEARCH (TAG "u2") UID REMOVEFROM (2 3)`)
	send(t, c, "x3 EXPUNGE")
	if lines, _ := until("x3"); !slices.Equal(lines, []string{`* ESEARCH (TAG "u1") REMOVEFROM (0 2)`, "* 2 EXPUNGE"}) {
		t.Fatalf("expunge: %q", lines)
	}
	check("c1 CANCELUPDATE \"u1\" \"u2\"")
	check(`s4 STORE 1 -FLAGS.SILENT (\Seen)`)
}
