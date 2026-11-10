package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
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

	send(t, conn, "c3 SELECT INBOX (CONDSTORE)")
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

// TestIMAPFetchChangedSince checks the CHANGEDSINCE FETCH modifier (RFC 7162): only messages
// changed after the given mod-sequence are returned, each with MODSEQ.
func TestIMAPFetchChangedSince(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	for _, body := range []string{"one", "two"} {
		if _, err := inbox.Deliver(ctx, accID, []byte("From: a@example.com\r\n\r\n"+body+"\r\n")); err != nil {
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
	send(t, conn, "k1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "k1 OK")
	send(t, conn, "k2 SELECT INBOX (CONDSTORE)")
	var line, highest string
	for !strings.HasPrefix(line, "k2 OK") {
		line, _ = read.ReadString('\n')
		if v, ok := strings.CutPrefix(line, "* OK [HIGHESTMODSEQ "); ok {
			highest, _, _ = strings.Cut(v, "]")
		}
	}
	if highest == "" {
		t.Fatal("no HIGHESTMODSEQ on SELECT")
	}

	// Nothing changed since SELECT.
	send(t, conn, "k3 UID FETCH 1:* (FLAGS) (CHANGEDSINCE "+highest+")")
	expectPrefix(t, read, "k3 OK")

	send(t, conn, `k4 STORE 2 +FLAGS.SILENT (\Flagged)`)
	expectPrefix(t, read, "k4 OK")
	send(t, conn, "k5 FETCH 1:* (FLAGS) (CHANGEDSINCE "+highest+")")
	line, _ = read.ReadString('\n')
	if !strings.HasPrefix(line, "* 2 FETCH (FLAGS (") || !strings.Contains(line, `\Flagged`) || !strings.Contains(line, "MODSEQ (") {
		t.Fatalf("changedsince fetch %q", line)
	}
	expectPrefix(t, read, "k5 OK")

	send(t, conn, "k6 FETCH 1:* (FLAGS) (CHANGEDSINCE x)")
	expectPrefix(t, read, "k6 BAD")
}

// TestIMAPSelectCondstoreParam checks SELECT with the RFC 7162 select parameter opens the
// mailbox (not a new one named "INBOX (CONDSTORE)"), and that unknown parameters get BAD.
func TestIMAPSelectCondstoreParam(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	if _, err := inbox.Deliver(ctx, accID, []byte("From: a@example.com\r\n\r\nx\r\n")); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "p1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "p1 OK")

	send(t, conn, "p2 SELECT INBOX (CONDSTORE)")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	for line := ""; !strings.HasPrefix(line, "p2 "); {
		line, _ = read.ReadString('\n')
		if strings.HasPrefix(line, "p2 ") && !strings.HasPrefix(line, "p2 OK") {
			t.Fatalf("select %q", line)
		}
	}

	send(t, conn, `p3 EXAMINE "INBOX" (FOO)`)
	expectPrefix(t, read, "p3 BAD")

	send(t, conn, `p4 LIST "" "*"`)
	for line := ""; !strings.HasPrefix(line, "p4 OK"); {
		if line, err = read.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(line, "CONDSTORE") || strings.Contains(line, "FOO") {
			t.Fatalf("select parameter became a mailbox: %q", line)
		}
	}
}

// TestIMAPStoreUnchangedSinceModified checks a failed conditional STORE answers
// OK [MODIFIED set] naming the messages left unchanged (RFC 7162 3.1.3).
func TestIMAPStoreUnchangedSinceModified(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	for _, body := range []string{"one", "two"} {
		if _, err := inbox.Deliver(ctx, accID, []byte("From: a@example.com\r\n\r\n"+body+"\r\n")); err != nil {
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
	send(t, conn, "m1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "m1 OK")
	send(t, conn, "m2 SELECT INBOX (CONDSTORE)")
	for line := ""; !strings.HasPrefix(line, "m2 OK"); {
		line, _ = read.ReadString('\n')
	}

	// Message 2 changes, so its mod-sequence moves past message 1's.
	send(t, conn, `m3 STORE 2 +FLAGS.SILENT (\Flagged)`)
	expectPrefix(t, read, "m3 OK")
	send(t, conn, "m4 FETCH 1 (MODSEQ)")
	line, _ := read.ReadString('\n')
	_, v, _ := strings.Cut(line, "MODSEQ (")
	mod1, _, _ := strings.Cut(v, ")")
	expectPrefix(t, read, "m4 OK")

	send(t, conn, `m5 STORE 1:2 (UNCHANGEDSINCE `+mod1+`) +FLAGS.SILENT (\Seen)`)
	line, _ = read.ReadString('\n')
	if line != "m5 OK [MODIFIED 2] Conditional STORE failed\r\n" {
		t.Fatalf("store %q", line)
	}

	send(t, conn, `m6 UID STORE 1:2 (UNCHANGEDSINCE 1) +FLAGS.SILENT (\Deleted)`)
	line, _ = read.ReadString('\n')
	if !strings.HasPrefix(line, "m6 OK [MODIFIED 1:2]") {
		t.Fatalf("uid store %q", line)
	}
}

// TestIMAPCondstoreEnablingCommand checks RFC 7162 3.1: no mod-sequences before a CONDSTORE
// enabling command; the first one with a mailbox selected reports HIGHESTMODSEQ, later ones don't,
// and flag changes then carry UID and MODSEQ.
func TestIMAPCondstoreEnablingCommand(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\n\r\nenable\r\n")); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "e1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "e1 OK")
	send(t, conn, "e2 SELECT INBOX")
	for line := ""; !strings.HasPrefix(line, "e2 OK"); {
		line, _ = read.ReadString('\n')
		if strings.Contains(line, "HIGHESTMODSEQ") {
			t.Fatalf("HIGHESTMODSEQ before CONDSTORE was enabled: %q", line)
		}
	}
	send(t, conn, `e3 STORE 1 +FLAGS (\Flagged)`)
	expectPrefix(t, read, `* 1 FETCH (FLAGS (\Flagged \Recent))`)
	expectPrefix(t, read, "e3 OK")

	send(t, conn, "e4 FETCH 1 (MODSEQ)")
	expectPrefix(t, read, "* OK [HIGHESTMODSEQ ")
	expectPrefix(t, read, "* 1 FETCH (MODSEQ (")
	expectPrefix(t, read, "e4 OK")
	send(t, conn, "e5 FETCH 1 (MODSEQ)")
	expectPrefix(t, read, "* 1 FETCH (MODSEQ (")
	expectPrefix(t, read, "e5 OK")
	send(t, conn, `e6 STORE 1 -FLAGS (\Flagged)`)
	expectPrefix(t, read, `* 1 FETCH (UID 1 FLAGS (\Recent) MODSEQ (`)
	expectPrefix(t, read, "e6 OK")
}
