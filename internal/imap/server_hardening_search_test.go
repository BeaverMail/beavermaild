package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestIMAPHardeningAndSearchHeader(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("From: tb@example.com\r\nMessage-ID: <tb-needle@example.com>\r\nSubject: tb\r\n\r\nbody\r\n")
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

	if _, err := fmt.Fprintf(conn, "evil\rtag NOOP\r\n"); err != nil {
		t.Fatal(err)
	}
	line, err := read.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "* BAD invalid tag") {
		t.Fatalf("bad tag response %q err %v", line, err)
	}

	send(t, conn, "h1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "h1 OK")
	send(t, conn, "h2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	expectPrefix(t, read, "* OK [UIDVALIDITY")
	expectPrefix(t, read, "h2 OK")

	send(t, conn, fmt.Sprintf("h3 CREATE \"bad%cname\"", '\r'))
	expectPrefix(t, read, "h3 BAD mailbox name syntax")

	send(t, conn, `h4 SEARCH HEADER Message-ID tb-needle@example.com`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "h4 OK")
}
