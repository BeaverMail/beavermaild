package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestIMAPSortAndThread(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw1 := []byte("From: a@b\r\nSubject: beta\r\nDate: Fri, 2 Jan 2025 10:00:00 +0000\r\nMessage-ID: <m1@x>\r\n\r\none\r\n")
	raw2 := []byte("From: a@b\r\nSubject: alpha\r\nDate: Fri, 1 Jan 2025 10:00:00 +0000\r\nMessage-ID: <m2@x>\r\nIn-Reply-To: <m1@x>\r\nReferences: <m1@x>\r\n\r\ntwo\r\n")
	if _, err := inbox.Deliver(ctx, accID, raw1); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, accID, raw2); err != nil {
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
	send(t, conn, "s2 CAPABILITY")
	line, _ := read.ReadString('\n')
	if !strings.Contains(line, "SORT") || !strings.Contains(line, "THREAD=REFERENCES") {
		t.Fatalf("caps %q", line)
	}
	expectPrefix(t, read, "s2 OK")
	send(t, conn, "s3 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 2 EXISTS")
	expectPrefix(t, read, "* 2 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "s3 OK")

	send(t, conn, "s4 SORT (SUBJECT) ALL")
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "* SORT") {
		t.Fatalf("sort %q", line)
	}
	expectPrefix(t, read, "s4 OK")

	send(t, conn, "s5 UID THREAD REFERENCES ALL")
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "* THREAD (") || !strings.Contains(line, ")") {
		t.Fatalf("thread %q", line)
	}
	expectPrefix(t, read, "s5 OK")
}
