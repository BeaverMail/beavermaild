package imap_test

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
)

func TestIMAPBodySectionFetch(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("Content-Type: multipart/mixed; boundary=mix\r\n\r\n" +
		"--mix\r\nContent-Type: text/plain\r\n\r\nhello\r\n" +
		"--mix\r\nContent-Type: application/pdf; name=a.pdf\r\n\r\n%PDF-1.4\r\n" +
		"--mix--\r\n")
	if _, err := inbox.Deliver(ctx, accID, raw); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "f1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "f1 OK")
	send(t, conn, "f2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "f2 OK")

	send(t, conn, "f3 FETCH 1 (BODY.PEEK[2])")
	line, err := read.ReadString('\n')
	if err != nil || !strings.Contains(line, "BODY[2]") || strings.Contains(line, "BODY.PEEK") {
		t.Fatalf("prelude %q err %v", line, err)
	}
	n, err := literalSize(line)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(read, body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "application/pdf") || !strings.Contains(string(body), "%PDF") {
		t.Fatalf("attachment %q", body)
	}
	expectPrefix(t, read, ")")
	expectPrefix(t, read, "f3 OK")

	send(t, conn, "f4 FETCH 1 (RFC822.HEADER)")
	line, err = read.ReadString('\n')
	if err != nil || !strings.Contains(line, "RFC822.HEADER") {
		t.Fatalf("hdr prelude %q", line)
	}
	n, err = literalSize(line)
	if err != nil {
		t.Fatal(err)
	}
	body = make([]byte, n)
	if _, err := io.ReadFull(read, body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "multipart/mixed") {
		t.Fatalf("header %q", body)
	}
	expectPrefix(t, read, ")")
	expectPrefix(t, read, "f4 OK")
}
