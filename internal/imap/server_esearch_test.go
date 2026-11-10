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
}
