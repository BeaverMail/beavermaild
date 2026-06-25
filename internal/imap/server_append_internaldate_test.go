package imap_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

// TestIMAPAppendInternalDate checks APPEND date-time is reflected in FETCH INTERNALDATE.
func TestIMAPAppendInternalDate(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("From: a@b.com\r\nSubject: dated\r\n\r\nbody\r\n")
	internalDate := `"25-Jun-2024 10:30:00 +0000"`

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "d1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "d1 OK")
	send(t, conn, "d2 SELECT Drafts")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* ")
	expectPrefix(t, read, "* OK")
	expectPrefix(t, read, "d2 OK")

	if _, err := fmt.Fprintf(conn, "d3 APPEND Drafts %s {%d}\r\n", internalDate, len(raw)); err != nil {
		t.Fatal(err)
	}
	expectPrefix(t, read, "+")
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "d3 OK")

	send(t, conn, "d4 SELECT Drafts")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* ")
	expectPrefix(t, read, "* OK")
	expectPrefix(t, read, "d4 OK")

	send(t, conn, "d5 FETCH 1 (INTERNALDATE)")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `INTERNALDATE "25-Jun-2024 10:30:00 +0000"`) {
		t.Fatalf("internaldate %q", line)
	}
	expectPrefix(t, read, "d5 OK")

	send(t, conn, "d6 FETCH 1 (BODY[])")
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "BODY[]") {
		t.Fatalf("body prelude %q", line)
	}
	n, err := literalSize(line)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(read, body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "dated") {
		t.Fatalf("body %q", body)
	}
	expectPrefix(t, read, ")")
	expectPrefix(t, read, "d6 OK")
}
