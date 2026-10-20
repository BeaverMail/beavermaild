package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestIMAPAppendUID(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "u1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "u1 OK")
	send(t, conn, "u2 CAPABILITY")
	line, _ := read.ReadString('\n')
	if !strings.Contains(line, "UIDPLUS") {
		t.Fatalf("caps %q", line)
	}
	expectPrefix(t, read, "u2 OK")

	raw := []byte("From: a@b\r\n\r\nuidplus\r\n")
	if _, err := fmt.Fprintf(conn, "u3 APPEND Drafts {%d}\r\n", len(raw)); err != nil {
		t.Fatal(err)
	}
	expectPrefix(t, read, "+")
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "APPENDUID") {
		t.Fatalf("append response %q", line)
	}
}

func TestIMAPCopyUIDAndClose(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\n\r\none\r\n")); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "c1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "c1 OK")
	send(t, conn, "c2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "c2 OK")
	send(t, conn, "c3 CREATE DestUID")
	expectPrefix(t, read, "c3 OK")
	send(t, conn, "c4 UID COPY 1 DestUID")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "COPYUID") || !strings.Contains(line, "1") {
		t.Fatalf("copy uid %q", line)
	}

	send(t, conn, "c5 STORE 1 +FLAGS (\\Deleted)")
	expectPrefix(t, read, "* 1 FETCH")
	expectPrefix(t, read, "c5 OK")
	send(t, conn, "c6 CLOSE")
	expectPrefix(t, read, "c6 OK")
	send(t, conn, "c7 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "c7 OK")
	send(t, conn, "c8 SELECT DestUID")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "c8 OK")
}

func TestIMAPUnselect(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "x1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "x1 OK")
	send(t, conn, "x2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "x2 OK")
	send(t, conn, "x3 UNSELECT")
	expectPrefix(t, read, "x3 OK UNSELECT completed")
	send(t, conn, "x4 FETCH 1 (FLAGS)")
	expectPrefix(t, read, "x4 NO not selected")
}

func TestIMAPCheck(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "k1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "k1 OK")
	send(t, conn, "k2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 0 EXISTS")
	expectPrefix(t, read, "* 0 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "k2 OK")
	send(t, conn, "k3 CHECK")
	expectPrefix(t, read, "k3 OK CHECK completed")
}
