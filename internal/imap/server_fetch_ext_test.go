package imap_test

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
)

// readResponse reads one response line including any literals it carries.
func readResponse(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(line)
		if !strings.HasSuffix(line, "}\r\n") {
			return b.String()
		}
		n, err := literalSize(strings.TrimSuffix(line, "\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			t.Fatal(err)
		}
		b.Write(buf)
	}
}

// TestIMAPFetch8BitStringsAsLiterals: decoded non-ASCII names and filenames must not be sent
// as quoted strings (7-bit only in IMAP4rev1).
func TestIMAPFetch8BitHeaderTextAsEncodedWords(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := "From: =?UTF-8?Q?Jos=C3=A9?= <jose@example.com>\r\n" +
		"Subject: test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n" +
		"--b\r\nContent-Type: application/pdf; name*=UTF-8''fattura%C3%A0.pdf\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\nAAAA\r\n--b--\r\n"
	if _, err := inbox.Deliver(ctx, accID, []byte(raw)); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "e1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "e1 OK")
	send(t, conn, "e2 EXAMINE INBOX")
	for line := ""; !strings.HasPrefix(line, "e2 OK"); {
		line = readResponse(t, read)
	}

	send(t, conn, "e3 FETCH 1 (ENVELOPE BODYSTRUCTURE)")
	resp := readResponse(t, read)
	expectPrefix(t, read, "e3 OK")
	// RFC 3501 4.3.1: 8-bit text only with its charset identified. Go's parsers decode RFC 2047
	// and RFC 2231, so the server sends the text back as an RFC 2047 word: 7-bit, charset named.
	if !strings.Contains(resp, `(("=?utf-8?q?Jos=C3=A9?=" NIL "jose" "example.com"))`) {
		t.Fatalf("envelope name: %q", resp)
	}
	if !strings.Contains(resp, `("NAME" "=?utf-8?q?fattura=C3=A0.pdf?=")`) {
		t.Fatalf("filename: %q", resp)
	}
	for i := 0; i < len(resp); i++ {
		if resp[i] >= 0x80 {
			t.Fatalf("8-bit byte in the response: %q", resp)
		}
	}
}

func TestIMAPFetchPartial(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	if _, err := inbox.Deliver(ctx, accID, []byte("Subject: p\r\n\r\n0123456789\r\n")); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "p1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "p1 OK")
	send(t, conn, "p2 EXAMINE INBOX")
	for line := ""; !strings.HasPrefix(line, "p2 OK"); {
		line = readResponse(t, read)
	}

	send(t, conn, "p3 FETCH 1 (BODY.PEEK[TEXT]<2.4> BODY.PEEK[TEXT]<100.5>)")
	resp := readResponse(t, read)
	expectPrefix(t, read, "p3 OK")
	if want := "* 1 FETCH (BODY[TEXT]<2> {4}\r\n2345 BODY[TEXT]<100> {0}\r\n)\r\n"; resp != want {
		t.Fatalf("partial %q want %q", resp, want)
	}
}

// TestIMAPValidCommandsNotBAD covers commands imaptest saw rejected with BAD: reversed sequence
// ranges, FETCH BODY and the FAST/ALL/FULL macros, and SEARCH with an empty string.
func TestIMAPValidCommandsNotBAD(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	multi := "Subject: m\r\nX-Extra: 1\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n"
	for _, raw := range []string{multi, "From: a@example.com\r\n\r\nx\r\n"} {
		if _, err := inbox.Deliver(ctx, accID, []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "v1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "v1 OK")
	send(t, conn, "v2 EXAMINE INBOX")
	for line := ""; !strings.HasPrefix(line, "v2 OK"); {
		line = readResponse(t, read)
	}

	send(t, conn, "v3 FETCH 2:1 UID")
	expectPrefix(t, read, "* 1 FETCH (UID ")
	expectPrefix(t, read, "* 2 FETCH (UID ")
	expectPrefix(t, read, "v3 OK")

	// BODY is BODYSTRUCTURE without extension data: no multipart parameter list.
	send(t, conn, "v4 FETCH 1 BODY")
	if line := readResponse(t, read); !strings.HasSuffix(line, ` "MIXED"))`+"\r\n") {
		t.Fatalf("fetch body %q", line)
	}
	expectPrefix(t, read, "v4 OK")

	send(t, conn, "v5 FETCH 2 FULL")
	line := readResponse(t, read)
	for _, item := range []string{"FLAGS ", "INTERNALDATE ", "RFC822.SIZE ", "ENVELOPE ", "BODY ("} {
		if !strings.Contains(line, item) {
			t.Fatalf("fetch full missing %s: %q", item, line)
		}
	}
	expectPrefix(t, read, "v5 OK")

	send(t, conn, `v6 SEARCH SUBJECT ""`)
	expectPrefix(t, read, "* SEARCH 1 2")
	expectPrefix(t, read, "v6 OK")

	// HEADER field "" matches only messages that have the field.
	send(t, conn, `v7 SEARCH HEADER X-Extra ""`)
	if line := readResponse(t, read); line != "* SEARCH 1\r\n" {
		t.Fatalf("header presence %q", line)
	}
	expectPrefix(t, read, "v7 OK")
}

// TestIMAPFetchSetsSeen checks the implicit \Seen of RFC 3501: BODY[...] without PEEK and
// RFC822.TEXT set it and report FLAGS; BODY.PEEK and a read-only mailbox do not.
func TestIMAPFetchSetsSeen(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	for range 2 {
		if _, err := inbox.Deliver(ctx, accID, []byte("Subject: s\r\n\r\nbody\r\n")); err != nil {
			t.Fatal(err)
		}
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "s1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "s1 OK")
	open := func(tag, cmd string) {
		send(t, conn, tag+" "+cmd+" INBOX")
		for line := ""; !strings.HasPrefix(line, tag+" OK"); {
			line = readResponse(t, read)
		}
	}
	fetch := func(tag, cmd string) string {
		send(t, conn, tag+" FETCH "+cmd)
		line := readResponse(t, read)
		expectPrefix(t, read, tag+" OK")
		return line
	}

	open("s2", "EXAMINE")
	if line := fetch("s3", "1 BODY[TEXT]"); strings.Contains(line, `\Seen`) {
		t.Fatalf("read-only set seen: %q", line)
	}

	open("s4", "SELECT")
	if line := fetch("s5", "1 BODY.PEEK[TEXT]"); strings.Contains(line, "FLAGS") {
		t.Fatalf("peek reported flags: %q", line)
	}
	if line := fetch("s6", "1 BODY[TEXT]"); !strings.Contains(line, `FLAGS (\Seen`) && !strings.Contains(line, `\Seen)`) {
		t.Fatalf("body[] did not set seen: %q", line)
	}
	if line := fetch("s7", "2 RFC822.TEXT"); !strings.Contains(line, `\Seen`) {
		t.Fatalf("rfc822.text did not set seen: %q", line)
	}
	// Already seen: no new FLAGS item.
	if line := fetch("s8", "1 BODY[TEXT]"); strings.Contains(line, "FLAGS") {
		t.Fatalf("seen again reported flags: %q", line)
	}
}
