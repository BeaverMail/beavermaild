package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestIMAPBodyStructureAndInternalDate(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("From: a@b.com\r\nSubject: bs\r\nContent-Type: text/plain\r\n\r\nbody line\r\n")
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
	send(t, conn, "b1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "b1 OK")
	send(t, conn, "b2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	expectPrefix(t, read, "* OK [UIDVALIDITY")
	expectPrefix(t, read, "b2 OK")

	send(t, conn, "b3 FETCH 1 (BODYSTRUCTURE INTERNALDATE)")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "BODYSTRUCTURE") || !strings.Contains(line, `"TEXT" "PLAIN"`) {
		t.Fatalf("bodystructure %q", line)
	}
	if !strings.Contains(line, "INTERNALDATE") {
		t.Fatalf("internaldate %q", line)
	}
	expectPrefix(t, read, "b3 OK")
}
