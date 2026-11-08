package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// TestIMAPListHasChildren reports \HasChildren when a nested mailbox exists.
func TestIMAPListHasChildren(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	if _, err := inbox.CreateMailbox(ctx, accID, "Work"); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.CreateMailbox(ctx, accID, "Work/Projects"); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "h1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "h1 OK")

	send(t, conn, `h2 LIST "" "Work"`)
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `\HasChildren`) || !strings.Contains(line, "Work") {
		t.Fatalf("parent list %q", line)
	}
	expectPrefix(t, read, "h2 OK")

	send(t, conn, `h3 LIST "" "Work/Projects"`)
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `\HasNoChildren`) || !strings.Contains(line, "Work/Projects") {
		t.Fatalf("child list %q", line)
	}
	expectPrefix(t, read, "h3 OK")
}
