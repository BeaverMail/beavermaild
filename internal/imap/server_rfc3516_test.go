package imap_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRFC3516Binary checks the BINARY audit fixes (.specs/audit/rfc3516.md): no \Seen on a failed
// BINARY fetch, BAD for malformed partials, literal8 outside APPEND and NUL in commands.
func TestRFC3516Binary(t *testing.T) {
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

	// RFC 3501 9: no string holds NUL, before login too; the literal is read, so nothing desyncs.
	send(t, c, "l0 LOGIN {5+}\r\nal\x00ce beaver")
	expectPrefix(t, r, "l0 BAD NUL")
	send(t, c, "l1 LOGIN alice@localhost beaver")
	expectPrefix(t, r, "l1 OK")
	lit := func(s string) string { return "{" + strconv.Itoa(len(s)) + "+}\r\n" + s }

	part := "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\nAGhp\r\n--b\r\n" +
		"Content-Transfer-Encoding: x-uuencode\r\n\r\nbegin\r\n--b--\r\n"
	send(t, c, "a1 APPEND INBOX ~"+lit(part))
	expectPrefix(t, r, "a1 OK")
	send(t, c, "s1 SELECT INBOX")
	for line := ""; !strings.HasPrefix(line, "s1 OK"); {
		line, _ = r.ReadString('\n')
	}

	// 4.3: UNKNOWN-CTE fails the FETCH, so the BINARY (not PEEK) sets no \Seen.
	send(t, c, "f1 FETCH 1 (BINARY[2])")
	expectPrefix(t, r, "f1 NO [UNKNOWN-CTE]")
	send(t, c, "f2 FETCH 1 (FLAGS)")
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "* 1 FETCH") || strings.Contains(line, `\Seen`) {
		t.Fatalf("failed BINARY fetch set \\Seen: %q", line)
	}
	expectPrefix(t, r, "f2 OK")
	// A successful BINARY still does.
	send(t, c, "f3 FETCH 1 (BINARY[1])")
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "* 1 FETCH") || !strings.Contains(line, `\Seen`) {
		t.Fatalf("BINARY fetch without \\Seen: %q", line)
	}
	_, _ = io.ReadFull(r, make([]byte, 3))
	expectPrefix(t, r, ")")
	expectPrefix(t, r, "f3 OK")

	// 7: partial = "<" number "." nz-number ">", 32-bit numbers; none on BINARY.SIZE.
	for i, item := range []string{"BINARY.PEEK[1]<", "BINARY.PEEK[1]<1.0>", "BINARY.PEEK[1]<4294967296.1>", "BODY.PEEK[1]<x.1>", "BINARY.SIZE[1]<0.2>"} {
		send(t, c, fmt.Sprintf("p%d FETCH 1 (%s)", i, item))
		expectPrefix(t, r, fmt.Sprintf("p%d BAD", i))
	}
	send(t, c, "p9 FETCH 1 (BINARY.PEEK[1]<4294967295.1>)")
	expectPrefix(t, r, "* 1 FETCH (BINARY[1]<4294967295> {0}")
	expectPrefix(t, r, ")")
	expectPrefix(t, r, "p9 OK")

	// 7: literal8 is APPEND data only; a synchronizing one is refused before the continuation.
	send(t, c, "n1 SEARCH TEXT ~{2}")
	expectPrefix(t, r, "n1 BAD literal8")
	send(t, c, "n2 SEARCH TEXT ~{2+}\r\nhi")
	expectPrefix(t, r, "n2 BAD literal8")
	// RFC 3501 9: NUL in a literal or a quoted string; APPEND keywords and mailbox too.
	send(t, c, "n3 SEARCH TEXT {3+}\r\nh\x00i")
	expectPrefix(t, r, "n3 BAD NUL")
	send(t, c, "n4 SEARCH TEXT \"h\x00i\"")
	expectPrefix(t, r, "n4 BAD NUL")
	send(t, c, "n5 APPEND INBOX (k\x00w) "+lit("Subject: x\r\n\r\nx\r\n"))
	expectPrefix(t, r, "n5 BAD")
	send(t, c, "n6 APPEND IN\x00BOX "+lit("Subject: x\r\n\r\nx\r\n"))
	expectPrefix(t, r, "n6 BAD")
	send(t, c, "n7 NOOP")
	expectPrefix(t, r, "n7 OK")
}

// TestRFC3516BinaryRepeatedSections is the CVE-2026-107581 class: a FETCH naming one BINARY part
// many times decodes it once, instead of holding one decoded copy per item. Not parallel, so the
// allocation count is this test's own.
func TestRFC3516BinaryRepeatedSections(t *testing.T) {
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(c)
	expectPrefix(t, r, "* OK")
	send(t, c, "l1 LOGIN alice@localhost beaver")
	expectPrefix(t, r, "l1 OK")

	// 2 MiB base64 attachment, inside a message/rfc822 labelled base64 (RFC 2045 6.4 forbids it):
	// the composite is returned as stored, so the nested levels never decode the data again.
	var enc strings.Builder
	for s := base64.StdEncoding.EncodeToString(make([]byte, 2<<20)); s != ""; {
		n := min(76, len(s))
		enc.WriteString(s[:n] + "\r\n")
		s = s[n:]
	}
	inner := "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" + enc.String()
	msg := "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n" +
		"Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n" + inner + "--b--\r\n"
	send(t, c, "a1 APPEND INBOX {"+strconv.Itoa(len(msg))+"+}\r\n"+msg)
	expectPrefix(t, r, "a1 OK")
	send(t, c, "s1 SELECT INBOX")
	for line := ""; !strings.HasPrefix(line, "s1 OK"); {
		line, _ = r.ReadString('\n')
	}
	send(t, c, "f1 FETCH 1 (BINARY.SIZE[1] BINARY.SIZE[1.1])")
	expectPrefix(t, r, fmt.Sprintf("* 1 FETCH (BINARY.SIZE[1] %d BINARY.SIZE[1.1] %d)", len(inner)-2, 2<<20)) // the last CRLF is the delimiter's (RFC 2046 5.1.1)
	expectPrefix(t, r, "f1 OK")

	items := strings.Repeat("BINARY.SIZE[1.1] BINARY.SIZE[1] ", 300)
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	send(t, c, "f2 FETCH 1 ("+strings.TrimSpace(items)+")")
	expectPrefix(t, r, "* 1 FETCH")
	expectPrefix(t, r, "f2 OK")
	runtime.ReadMemStats(&m1)
	// One decode is 2 MiB; 600 of them were over 1 GiB.
	if got := (m1.TotalAlloc - m0.TotalAlloc) >> 20; got > 64 {
		t.Fatalf("600 BINARY.SIZE items allocated %d MiB", got)
	}
}
