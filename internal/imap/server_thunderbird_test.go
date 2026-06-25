package imap_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

// TestIMAPThunderbirdSync mimics Betterbird/Thunderbird post-login folder sync.
func TestIMAPThunderbirdSync(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: thunderbird sync\r\n" +
		"Date: Wed, 25 Jun 2026 12:00:00 +0000\r\n\r\n" +
		"hello\r\n")
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
	send(t, conn, "t1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "t1 OK")
	send(t, conn, "t2 ENABLE CONDSTORE")
	expectPrefix(t, read, "* ENABLED CONDSTORE")
	expectPrefix(t, read, "t2 OK")
	send(t, conn, "t3 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"UIDVALIDITY", "UIDNEXT 2", "UNSEEN", "HIGHESTMODSEQ", `PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)`} {
		if !strings.Contains(line, want) {
			t.Fatalf("select ok %q missing %q", line, want)
		}
	}
	expectPrefix(t, read, "t3 OK")

	send(t, conn, "t4 UID FETCH 1:* (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE ENVELOPE MODSEQ)")
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"UID 1", "ENVELOPE", "BODYSTRUCTURE", "MODSEQ (", `"thunderbird sync"`} {
		if !strings.Contains(line, want) {
			t.Fatalf("uid fetch %q missing %q", line, want)
		}
	}
	expectPrefix(t, read, "t4 OK")
}

// TestIMAPBetterbirdFlagsFetch matches Betterbird post-SELECT UID FETCH 1:* (FLAGS) with sparse UIDs.
func TestIMAPBetterbirdFlagsFetch(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	for i, subj := range []string{"a", "b", "c"} {
		raw := []byte(fmt.Sprintf("Subject: %s\r\n\r\nbody%d\r\n", subj, i))
		if _, err := inbox.Deliver(ctx, accID, raw); err != nil {
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
	send(t, conn, "b1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "b1 OK")
	send(t, conn, "b2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 3 EXISTS")
	expectPrefix(t, read, "* ")
	expectPrefix(t, read, "* OK")
	expectPrefix(t, read, "b2 OK")

	send(t, conn, "b3 UID FETCH 1:* (FLAGS)")
	for i := 0; i < 3; i++ {
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(line, "UID ") || !strings.Contains(line, "FLAGS") || !strings.Contains(line, "MODSEQ (") {
			t.Fatalf("betterbird flags fetch %q", line)
		}
	}
	expectPrefix(t, read, "b3 OK")
}

// TestIMAPBetterbirdHeaderFetch matches TB header download without unsolicited MODSEQ.
func TestIMAPBetterbirdHeaderFetch(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: header test\r\n\r\nbody\r\n")
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
	send(t, conn, "h1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "h1 OK")
	send(t, conn, "h2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* ")
	expectPrefix(t, read, "* OK")
	expectPrefix(t, read, "h2 OK")

	send(t, conn, "h3 UID FETCH 1 (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From Subject)])")
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, "MODSEQ") || strings.Contains(line, "BODY.PEEK") {
		t.Fatalf("metadata fetch must not include MODSEQ or BODY: %q", line)
	}
	for _, want := range []string{"UID 1", "RFC822.SIZE", "FLAGS"} {
		if !strings.Contains(line, want) {
			t.Fatalf("metadata fetch %q missing %q", line, want)
		}
	}
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "BODY[HEADER.FIELDS") || strings.Contains(line, "BODY.PEEK") || !strings.Contains(line, "{") {
		t.Fatalf("header prelude %q", line)
	}
	n, err := literalSize(line)
	if err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, n)
	if _, err := io.ReadFull(read, hdr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hdr), "header test") {
		t.Fatalf("header body %q", hdr)
	}
	expectPrefix(t, read, ")")
	expectPrefix(t, read, "h3 OK")
}

// TestIMAPBetterbirdFullHeaderFields matches the exact Betterbird header download command.
func TestIMAPBetterbirdFullHeaderFields(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("From: info@google.com\r\nTo: bob@example.com\r\nSubject: full fields\r\n\r\nbody\r\n")
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
	send(t, conn, "f1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "f1 OK")
	send(t, conn, "f2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* ")
	expectPrefix(t, read, "* OK")
	expectPrefix(t, read, "f2 OK")

	cmd := "f3 UID FETCH 1 (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To Cc Bcc Subject Date Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type Reply-To)])"
	send(t, conn, cmd)
	meta, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(meta, "BODY.PEEK") || strings.Contains(meta, "{") {
		t.Fatalf("metadata line must not include body literal: %q", meta)
	}
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "BODY[HEADER.FIELDS") || strings.Contains(line, "BODY.PEEK") || !strings.Contains(line, "{") {
		t.Fatalf("body prelude %q", line)
	}
	n, err := literalSize(line)
	if err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, n)
	if _, err := io.ReadFull(read, hdr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hdr), "info@google.com") {
		t.Fatalf("header body %q", hdr)
	}
	expectPrefix(t, read, ")")
	expectPrefix(t, read, "f3 OK")
}
