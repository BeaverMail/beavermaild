package imap_test

import (
	"bufio"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestIMAPQResync checks RFC 7162 QRESYNC end to end: VANISHED replaces EXPUNGE once enabled, a
// SELECT with the client's cached state reports what vanished and changed since, UID FETCH
// (CHANGEDSINCE n VANISHED) does the same, and QRESYNC needs ENABLE first.
func TestIMAPQResync(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	for i := range 4 {
		if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\n\r\nqresync "+strconv.Itoa(i)+"\r\n")); err != nil {
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
	number := func(lines []string, re string) string {
		for _, l := range lines {
			if m := regexp.MustCompile(re).FindStringSubmatch(l); m != nil {
				return m[1]
			}
		}
		t.Fatalf("no %s in %q", re, lines)
		return ""
	}
	expectPrefix(t, r, "* OK")
	send(t, c, "l1 LOGIN alice@localhost beaver")
	until("l1")

	send(t, c, "q0 SELECT INBOX (QRESYNC (1 1))")
	if _, tagged := until("q0"); !strings.HasPrefix(tagged, "q0 BAD") {
		t.Fatalf("QRESYNC before ENABLE: %q", tagged)
	}
	send(t, c, "q1 ENABLE QRESYNC")
	if lines, _ := until("q1"); !slices.Contains(lines, "* ENABLED QRESYNC") {
		t.Fatalf("enable: %q", lines)
	}
	send(t, c, "q2 SELECT INBOX")
	lines, _ := until("q2")
	uidValidity := number(lines, `UIDVALIDITY (\d+)`)
	modSeq := number(lines, `HIGHESTMODSEQ (\d+)`)

	send(t, c, `q3 STORE 2 +FLAGS.SILENT (\Deleted)`)
	until("q3")
	send(t, c, "q4 EXPUNGE")
	if lines, _ := until("q4"); !slices.Equal(lines, []string{"* VANISHED 2"}) {
		t.Fatalf("expunge with QRESYNC: %q", lines)
	}
	send(t, c, `q5 STORE 2 +FLAGS.SILENT (\Flagged)`) // UID 3
	until("q5")

	send(t, c, "q6 SELECT INBOX (QRESYNC ("+uidValidity+" "+modSeq+"))")
	lines, tagged := until("q6")
	if !strings.HasPrefix(tagged, "q6 OK") || !strings.HasPrefix(lines[0], "* OK [CLOSED]") || !slices.Contains(lines, "* VANISHED (EARLIER) 2") {
		t.Fatalf("select qresync: %q %q", lines, tagged)
	}
	var fetches []string
	for _, l := range lines {
		if strings.Contains(l, " FETCH ") {
			fetches = append(fetches, l)
		}
	}
	if len(fetches) != 1 || !strings.HasPrefix(fetches[0], `* 2 FETCH (UID 3 FLAGS (\Flagged`) || !strings.Contains(fetches[0], "MODSEQ (") {
		t.Fatalf("changed since %s: %q", modSeq, fetches)
	}

	send(t, c, "q7 UID FETCH 1:* (FLAGS) (CHANGEDSINCE "+modSeq+" VANISHED)")
	lines, _ = until("q7")
	if len(lines) != 2 || lines[0] != "* VANISHED (EARLIER) 2" || !strings.Contains(lines[1], "UID 3") {
		t.Fatalf("uid fetch vanished: %q", lines)
	}
	send(t, c, "q8 FETCH 1:* (FLAGS) (CHANGEDSINCE "+modSeq+" VANISHED)")
	if _, tagged := until("q8"); !strings.HasPrefix(tagged, "q8 BAD") {
		t.Fatalf("VANISHED without UID: %q", tagged)
	}
	// Flag changes carry the UID once CONDSTORE is on (RFC 7162 3.2.4).
	send(t, c, `qa STORE 1 +FLAGS ($Label1)`)
	if lines, _ := until("qa"); !slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "* 1 FETCH (UID 1 FLAGS (") }) {
		t.Fatalf("store without UID: %q", lines)
	}
	// Reselecting keeps announcing a keyword no message uses any more: the client's cache may.
	send(t, c, `qb STORE 1 -FLAGS.SILENT ($Label1)`)
	until("qb")
	send(t, c, "qc SELECT INBOX")
	if lines, _ := until("qc"); !slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "* FLAGS (") && strings.Contains(l, "$Label1") }) {
		t.Fatalf("keyword dropped on reselect: %q", lines)
	}
	// A failed SELECT still closes the selected mailbox (RFC 3501 6.3.1).
	send(t, c, "q9 SELECT Nowhere")
	if lines, tagged := until("q9"); len(lines) != 1 || !strings.HasPrefix(lines[0], "* OK [CLOSED]") || !strings.HasPrefix(tagged, "q9 NO") {
		t.Fatalf("failed select: %q %q", lines, tagged)
	}
	send(t, c, "q10 FETCH 1 FLAGS")
	if _, tagged := until("q10"); !strings.HasPrefix(tagged, "q10 NO") {
		t.Fatalf("mailbox still selected after a failed SELECT: %q", tagged)
	}
}
