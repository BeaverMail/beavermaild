package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestIMAPListPatternAndSpecialUse(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("From: smoke@example.com\r\nSubject: list test\r\n\r\nbody\r\n")
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
	send(t, conn, "l1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "l1 OK")
	send(t, conn, "l2 CAPABILITY")
	line, _ := read.ReadString('\n')
	if !strings.Contains(line, "SPECIAL-USE") {
		t.Fatalf("caps %q", line)
	}
	expectPrefix(t, read, "l2 OK")

	send(t, conn, `l3 LIST "" "Sent"`)
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `\Sent`) || !strings.Contains(line, "Sent") {
		t.Fatalf("sent list %q", line)
	}
	expectPrefix(t, read, "l3 OK")

	send(t, conn, `l4 LIST "" "NoSuch*"`)
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(line, "* LIST") {
		t.Fatalf("unexpected list %q", line)
	}
	if !strings.HasPrefix(line, "l4 OK") {
		expectPrefix(t, read, "l4 OK")
	}

	send(t, conn, "l5 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "l5 OK")

	send(t, conn, `l6 SEARCH SUBJECT list`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l6 OK")
	send(t, conn, `l7 SEARCH FROM smoke@example.com`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l7 OK")
	send(t, conn, `l8 SEARCH SINCE 01-Jan-2020`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l8 OK")
	send(t, conn, `l9 SEARCH TEXT list`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l9 OK")
	send(t, conn, `l10 SEARCH BODY body`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l10 OK")
	send(t, conn, `l11 SEARCH LARGER 10`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l11 OK")
}
