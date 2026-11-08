package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// TestIMAPIdleFlagsCrossSession checks another connection's STORE reaches an IDLE client.
func TestIMAPIdleFlagsCrossSession(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\n\r\nidle-flags\r\n")); err != nil {
		t.Fatal(err)
	}

	idleConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer idleConn.Close()
	idleRead := bufio.NewReader(idleConn)

	storeConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer storeConn.Close()
	storeRead := bufio.NewReader(storeConn)

	for _, c := range []struct {
		conn net.Conn
		read *bufio.Reader
	}{
		{idleConn, idleRead},
		{storeConn, storeRead},
	} {
		expectPrefix(t, c.read, "* OK")
		send(t, c.conn, "l1 LOGIN alice@localhost beaver")
		expectPrefix(t, c.read, "l1 OK")
	}
	send(t, idleConn, "l2 SELECT INBOX")
	expectPrefix(t, idleRead, "* FLAGS")
	expectPrefix(t, idleRead, "* 1 EXISTS")
	expectPrefix(t, idleRead, "* 1 RECENT")
	expectSelectOK(t, idleRead)
	expectPrefix(t, idleRead, "l2 OK")
	send(t, storeConn, "l2 SELECT INBOX")
	expectPrefix(t, storeRead, "* FLAGS")
	expectPrefix(t, storeRead, "* 1 EXISTS")
	expectPrefix(t, storeRead, "* 0 RECENT")
	expectSelectOK(t, storeRead)
	expectPrefix(t, storeRead, "l2 OK")

	send(t, idleConn, "l3 IDLE")
	expectPrefix(t, idleRead, "+ idling")

	send(t, storeConn, "l4 STORE 1 +FLAGS.SILENT (\\Seen)")
	expectPrefix(t, storeRead, "l4 OK")

	deadline := time.Now().Add(2 * time.Second)
	gotFlags := false
	for time.Now().Before(deadline) {
		line, err := idleRead.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(line, `FETCH (FLAGS (\Seen)`) {
			gotFlags = true
			break
		}
	}
	if !gotFlags {
		t.Fatal("timeout waiting for FLAGS during IDLE")
	}
	send(t, idleConn, "DONE")
	expectPrefix(t, idleRead, "l3 OK IDLE terminated")
}

// TestIMAPIdleExpungeCrossSession checks EXPUNGE from another session reaches IDLE.
func TestIMAPIdleExpungeCrossSession(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\n\r\nidle-expunge\r\n")); err != nil {
		t.Fatal(err)
	}

	idleConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer idleConn.Close()
	idleRead := bufio.NewReader(idleConn)

	otherConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer otherConn.Close()
	otherRead := bufio.NewReader(otherConn)

	for _, c := range []struct {
		conn net.Conn
		read *bufio.Reader
	}{
		{idleConn, idleRead},
		{otherConn, otherRead},
	} {
		expectPrefix(t, c.read, "* OK")
		send(t, c.conn, "e1 LOGIN alice@localhost beaver")
		expectPrefix(t, c.read, "e1 OK")
	}
	send(t, idleConn, "e2 SELECT INBOX")
	expectPrefix(t, idleRead, "* FLAGS")
	expectPrefix(t, idleRead, "* 1 EXISTS")
	expectPrefix(t, idleRead, "* 1 RECENT")
	expectSelectOK(t, idleRead)
	expectPrefix(t, idleRead, "e2 OK")
	send(t, otherConn, "e2 SELECT INBOX")
	expectPrefix(t, otherRead, "* FLAGS")
	expectPrefix(t, otherRead, "* 1 EXISTS")
	expectPrefix(t, otherRead, "* 0 RECENT")
	expectSelectOK(t, otherRead)
	expectPrefix(t, otherRead, "e2 OK")

	send(t, idleConn, "e3 IDLE")
	expectPrefix(t, idleRead, "+ idling")

	send(t, otherConn, "e4 STORE 1 +FLAGS.SILENT (\\Deleted)")
	expectPrefix(t, otherRead, "e4 OK")
	send(t, otherConn, "e5 EXPUNGE")
	expectPrefix(t, otherRead, "* 1 EXPUNGE")
	expectPrefix(t, otherRead, "e5 OK")

	deadline := time.Now().Add(2 * time.Second)
	gotExpunge := false
	for time.Now().Before(deadline) {
		line, err := idleRead.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "* 1 EXPUNGE") {
			gotExpunge = true
			break
		}
	}
	if !gotExpunge {
		t.Fatal("timeout waiting for EXPUNGE during IDLE")
	}
	send(t, idleConn, "DONE")
	expectPrefix(t, idleRead, "e3 OK IDLE terminated")
}
