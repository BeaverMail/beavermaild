package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// TestIMAPUIDExpunge removes only deleted messages in the UID set.
func TestIMAPUIDExpunge(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	for _, body := range []string{"one\r\n", "two\r\n", "three\r\n"} {
		if _, err := inbox.Deliver(ctx, accID, []byte("Subject: x\r\n\r\n"+body)); err != nil {
			t.Fatal(err)
		}
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "u1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "u1 OK")
	send(t, conn, "u2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 3 EXISTS")
	expectPrefix(t, read, "* ")
	expectPrefix(t, read, "* OK")
	expectPrefix(t, read, "u2 OK")

	send(t, conn, "u3 UID STORE 1,3 +FLAGS (\\Deleted)")
	expectPrefix(t, read, "* 1 FETCH")
	expectPrefix(t, read, "* 3 FETCH")
	expectPrefix(t, read, "u3 OK")

	send(t, conn, "u4 UID EXPUNGE 1")
	expectPrefix(t, read, "* 1 EXPUNGE")
	expectPrefix(t, read, "u4 OK")

	send(t, conn, "u5 UID FETCH 1:* (UID)")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "UID 2") || strings.Contains(line, "UID 3") {
		t.Fatalf("remaining uids %q", line)
	}
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "UID 3") {
		t.Fatalf("second uid %q", line)
	}
	expectPrefix(t, read, "u5 OK")

	send(t, conn, "u6 UID EXPUNGE 3")
	expectPrefix(t, read, "* 2 EXPUNGE")
	expectPrefix(t, read, "u6 OK")

	send(t, conn, "u7 UID FETCH 1:* (UID)")
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "UID 2") || strings.Contains(line, "UID 3") {
		t.Fatalf("final uid %q", line)
	}
	expectPrefix(t, read, "u7 OK")
}

// TestIMAPUIDExpungeAll removes every deleted message when the UID set is omitted.
func TestIMAPUIDExpungeAll(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	for i := 0; i < 2; i++ {
		if _, err := inbox.Deliver(ctx, accID, []byte("Subject: y\r\n\r\nbody\r\n")); err != nil {
			t.Fatal(err)
		}
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "a1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "a1 OK")
	send(t, conn, "a2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 2 EXISTS")
	expectPrefix(t, read, "* ")
	expectPrefix(t, read, "* OK")
	expectPrefix(t, read, "a2 OK")

	send(t, conn, "a3 STORE 1 +FLAGS (\\Deleted)")
	expectPrefix(t, read, "* 1 FETCH")
	expectPrefix(t, read, "a3 OK")

	send(t, conn, "a4 UID EXPUNGE")
	expectPrefix(t, read, "* 1 EXPUNGE")
	expectPrefix(t, read, "a4 OK")

	send(t, conn, "a5 UID FETCH 1:* (UID)")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, "UID 1") {
		t.Fatalf("deleted uid still present %q", line)
	}
	expectPrefix(t, read, "a5 OK")
}
