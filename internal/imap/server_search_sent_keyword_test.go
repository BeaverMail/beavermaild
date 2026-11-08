package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestIMAPSearchSentKeyword(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("Date: Mon, 10 Jun 2024 12:00:00 +0000\r\nFrom: a@b.com\r\n\r\nx\r\n")
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
	send(t, conn, "k1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "k1 OK")
	send(t, conn, "k2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "k2 OK")

	send(t, conn, `k3 SEARCH SENTON 10-Jun-2024`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "k3 OK")

	send(t, conn, "k4 STORE 1 +FLAGS (Flag_007)")
	expectPrefix(t, read, "* 1 FETCH")
	expectPrefix(t, read, "k4 OK")

	send(t, conn, `k5 SEARCH KEYWORD Flag_007`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "k5 OK")

	send(t, conn, `k6 SEARCH OR KEYWORD Flag_007 KEYWORD nobody`)
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "* SEARCH 1") {
		t.Fatalf("or keyword %q", line)
	}
	expectPrefix(t, read, "k6 OK")
}
