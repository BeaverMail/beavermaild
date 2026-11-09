package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestIMAPCondstoreSelectAndStore(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("From: a@b.com\r\n\r\ncondstore\r\n")
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
	send(t, conn, "c1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "c1 OK")
	send(t, conn, "c2 CAPABILITY")
	line, _ := read.ReadString('\n')
	if !strings.Contains(line, "CONDSTORE") {
		t.Fatalf("caps %q", line)
	}
	expectPrefix(t, read, "c2 OK")

	send(t, conn, "c3 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	var selectLines string
	for !strings.HasPrefix(line, "c3 OK") {
		line, _ = read.ReadString('\n')
		selectLines += line
	}
	if !strings.Contains(selectLines, "[HIGHESTMODSEQ ") {
		t.Fatalf("select ok %q", selectLines)
	}

	send(t, conn, "c4 FETCH 1 (FLAGS MODSEQ)")
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "MODSEQ (") {
		t.Fatalf("fetch modseq %q", line)
	}
	expectPrefix(t, read, "c4 OK")

	send(t, conn, `c5 STORE 1 +FLAGS (\Seen)`)
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `\Seen`) || !strings.Contains(line, "MODSEQ (") {
		t.Fatalf("store fetch %q", line)
	}
	expectPrefix(t, read, "c5 OK")
}

// TestIMAPStatusHighestModSeq checks the ENABLE capability and STATUS HIGHESTMODSEQ (RFC 7162),
// which must match SELECT and grow after a flag change.
func TestIMAPStatusHighestModSeq(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	if _, err := inbox.Deliver(ctx, accID, []byte("From: a@example.com\r\n\r\nstatus\r\n")); err != nil {
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
	send(t, conn, "h2 CAPABILITY")
	line, _ := read.ReadString('\n')
	if !strings.Contains(line, " ENABLE ") {
		t.Fatalf("caps %q", line)
	}
	expectPrefix(t, read, "h2 OK")

	status := func(tag string) string {
		t.Helper()
		send(t, conn, tag+" STATUS INBOX (MESSAGES HIGHESTMODSEQ)")
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		expectPrefix(t, read, tag+" OK")
		const prefix = "* STATUS INBOX (MESSAGES 1 HIGHESTMODSEQ "
		if !strings.HasPrefix(line, prefix) {
			t.Fatalf("status %q", line)
		}
		return strings.TrimSuffix(strings.TrimPrefix(line, prefix), ")\r\n")
	}
	if status("h3") == "0" {
		t.Fatal("HIGHESTMODSEQ 0")
	}

	// SELECT clears \Recent, which bumps the mod-sequence: compare STATUS after it.
	send(t, conn, "h4 SELECT INBOX")
	var selectLines string
	for !strings.HasPrefix(line, "h4 OK") {
		line, _ = read.ReadString('\n')
		selectLines += line
	}
	before := status("h4s")
	if !strings.Contains(selectLines, "[HIGHESTMODSEQ "+before+"]") {
		t.Fatalf("select %q, status %s", selectLines, before)
	}

	send(t, conn, `h5 STORE 1 +FLAGS.SILENT (\Flagged)`)
	expectPrefix(t, read, "h5 OK")
	if after := status("h6"); after == before {
		t.Fatalf("HIGHESTMODSEQ unchanged after STORE: %s", after)
	}
}
