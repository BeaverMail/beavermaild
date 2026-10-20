package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestIMAPFetchEnvelope(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("From: Alice <alice@example.com>\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: envelope test\r\n" +
		"Message-ID: <env@test>\r\n\r\nbody\r\n")
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
	send(t, conn, "e1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "e1 OK")
	send(t, conn, "e2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "e2 OK")

	send(t, conn, "e3 FETCH 1 (ENVELOPE UID)")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ENVELOPE", `"envelope test"`, `"alice" "example.com"`, `"bob" "example.com"`, "UID 1"} {
		if !strings.Contains(line, want) {
			t.Fatalf("fetch %q missing %q", line, want)
		}
	}
	expectPrefix(t, read, "e3 OK")
}
