package imap_test

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestIMAPCatenate checks APPEND CATENATE (RFC 4469): TEXT and URL parts, BADURL with the rest of
// the command dropped, and TRYCREATE before any part is read.
func TestIMAPCatenate(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	expectPrefix(t, r, "* OK")
	send(t, c, "l1 LOGIN alice@localhost beaver")
	expectPrefix(t, r, "l1 OK")
	lit := func(s string) string { return "{" + strconv.Itoa(len(s)) + "+}\r\n" + s }

	send(t, c, "a1 APPEND Drafts "+lit("From: a@example.com\r\n\r\nhello\r\n"))
	expectPrefix(t, r, "a1 OK [APPENDUID 1 1]")
	send(t, c, `a2 APPEND Drafts CATENATE (URL "/Drafts;UIDVALIDITY=1/;UID=1/;SECTION=HEADER" TEXT `+
		lit("body\r\n")+` URL "imap://alice%40localhost@localhost/Drafts/;uid=1/;section=text/;partial=1.3")`)
	expectPrefix(t, r, "a2 OK [APPENDUID 1 2]")

	// A bad URL refuses the command; the TEXT literal the client already sends is dropped.
	send(t, c, `a3 APPEND Drafts CATENATE (URL "/Drafts;UIDVALIDITY=9/;UID=1" TEXT `+lit("x\r\n")+`)`)
	expectPrefix(t, r, "a3 NO [BADURL /Drafts;UIDVALIDITY=9/;UID=1]")
	// A sync literal after a bad URL is refused unsent: no continuation.
	send(t, c, `a4 APPEND Drafts CATENATE (URL "/Drafts/;UID=7" TEXT {3}`)
	expectPrefix(t, r, "a4 NO [BADURL")
	send(t, c, `a5 APPEND Nope CATENATE (TEXT `+lit("x\r\n")+` URL "/Drafts/;UID=1")`)
	expectPrefix(t, r, "a5 NO [TRYCREATE]")

	send(t, c, "s1 EXAMINE Drafts")
	for line := ""; !strings.HasPrefix(line, "s1 OK"); {
		line, _ = r.ReadString('\n')
	}
	want := "From: a@example.com\r\n\r\nbody\r\nell"
	send(t, c, "f1 FETCH 2 BODY.PEEK[]")
	expectPrefix(t, r, "* 2 FETCH (BODY[] {"+strconv.Itoa(len(want))+"}")
	if b := make([]byte, len(want)); func() bool { _, err := io.ReadFull(r, b); return err != nil || string(b) != want }() {
		t.Fatal("catenated body")
	}
	expectPrefix(t, r, ")")
	expectPrefix(t, r, "f1 OK")
	send(t, c, "s2 STATUS Drafts (MESSAGES)")
	expectPrefix(t, r, `* STATUS "Drafts" (MESSAGES 2)`)
}
