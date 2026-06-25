package imap_test

import (
	"bufio"
	"net"
	"testing"
)

func TestIMAPSearchOrNot(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	rawAlice := []byte("From: alice@example.com\r\nSubject: alpha\r\n\r\nbody\r\n")
	rawBob := []byte("From: bob@example.com\r\nSubject: beta\r\n\r\nbody\r\n")
	if _, err := inbox.Deliver(ctx, accID, rawAlice); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, accID, rawBob); err != nil {
		t.Fatal(err)
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
	send(t, conn, "s2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 2 EXISTS")
	expectPrefix(t, read, "* 2 RECENT")
	expectPrefix(t, read, "* OK [UIDVALIDITY")
	expectPrefix(t, read, "s2 OK")

	send(t, conn, `s3 SEARCH OR FROM alice@example.com SUBJECT beta`)
	expectPrefix(t, read, "* SEARCH 1 2")
	expectPrefix(t, read, "s3 OK")

	send(t, conn, `s4 SEARCH NOT FROM alice@example.com`)
	expectPrefix(t, read, "* SEARCH 2")
	expectPrefix(t, read, "s4 OK")
}
