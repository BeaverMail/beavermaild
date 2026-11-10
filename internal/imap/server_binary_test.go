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

// TestIMAPBinaryMultiAppend checks MULTIAPPEND (RFC 3502: all or nothing, one APPENDUID set),
// a literal8 APPEND and BINARY fetches (RFC 3516: decoded part, size, literal8 for NUL).
func TestIMAPBinaryMultiAppend(t *testing.T) {
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

	m1, m2 := "Subject: one\r\n\r\n1\r\n", "Subject: two\r\n\r\n2\r\n"
	send(t, c, "a1 APPEND Drafts "+lit(m1)+" (\\Seen) "+lit(m2))
	expectPrefix(t, r, "a1 OK [APPENDUID ")

	// A malformed second message spec fails the whole command: nothing is stored.
	send(t, c, "a2 APPEND Drafts "+lit(m1)+` "not a date" {5}`)
	expectPrefix(t, r, "a2 BAD")
	send(t, c, "a3 STATUS Drafts (MESSAGES)")
	expectPrefix(t, r, `* STATUS "Drafts" (MESSAGES 2)`)
	expectPrefix(t, r, "a3 OK")

	part := "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\nAGhp\r\n--b\r\n" +
		"Content-Transfer-Encoding: x-uuencode\r\n\r\nbegin\r\n--b--\r\n"
	send(t, c, "a4 APPEND Drafts ~"+lit(part))
	expectPrefix(t, r, "a4 OK")
	send(t, c, "s1 SELECT Drafts")
	for line := ""; !strings.HasPrefix(line, "s1 OK"); {
		line, _ = r.ReadString('\n')
	}
	send(t, c, "f1 FETCH 3 (BINARY.SIZE[1] BINARY.PEEK[1])")
	expectPrefix(t, r, "* 3 FETCH (BINARY.SIZE[1] 3 BINARY[1] ~{3}")
	if b := make([]byte, 3); func() bool { _, err := io.ReadFull(r, b); return err != nil || string(b) != "\x00hi" }() {
		t.Fatal("binary body")
	}
	expectPrefix(t, r, ")")
	expectPrefix(t, r, "f1 OK")
	send(t, c, "f2 FETCH 3 (BINARY.PEEK[2])")
	expectPrefix(t, r, "f2 NO [UNKNOWN-CTE]")
}
