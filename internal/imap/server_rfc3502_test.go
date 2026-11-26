package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRFC3502MultiAppendAtomic: a MULTIAPPEND that fails on its last message leaves the mailbox as
// it was (RFC 3502 6.3.11): no other session sees the first ones come and go, and UIDNEXT and
// HIGHESTMODSEQ do not move.
func TestRFC3502MultiAppendAtomic(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	dial := func() (net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		r := bufio.NewReader(c)
		expectPrefix(t, r, "* OK")
		send(t, c, "l1 LOGIN alice@localhost beaver")
		expectPrefix(t, r, "l1 OK")
		return c, r
	}
	a, ra := dial()
	defer a.Close()
	b, rb := dial()
	defer b.Close()
	lit := func(s string) string { return "{" + strconv.Itoa(len(s)) + "+}\r\n" + s }
	msg := func(i int) string { return fmt.Sprintf("Subject: m%d\r\n\r\nbody\r\n", i) }

	send(t, b, "e1 ENABLE QRESYNC")
	expectPrefix(t, rb, "* ENABLED")
	expectPrefix(t, rb, "e1 OK")
	send(t, b, "s1 SELECT INBOX")
	for line := ""; !strings.HasPrefix(line, "s1 OK"); {
		line, _ = rb.ReadString('\n')
	}
	status := func() string {
		send(t, a, "st STATUS INBOX (MESSAGES UIDNEXT HIGHESTMODSEQ)")
		line, _ := ra.ReadString('\n')
		expectPrefix(t, ra, "st OK")
		return line
	}

	// Keywords and flags land with the messages, in the same transaction.
	send(t, a, "a1 APPEND INBOX (kw1) "+lit(msg(1))+` (\Seen) `+lit(msg(2)))
	expectPrefix(t, ra, "a1 OK [APPENDUID 1 1:2]")
	send(t, b, "n1 NOOP")
	for line := ""; !strings.HasPrefix(line, "n1 OK"); {
		line, _ = rb.ReadString('\n')
	}
	before := status()

	limit := uint32(5)
	if err := inbox.SetQuotaLimits(ctx, accID, nil, &limit); err != nil {
		t.Fatal(err)
	}
	var cmd strings.Builder
	cmd.WriteString("a2 APPEND INBOX")
	for i := range 4 { // the 4th passes the 5-message limit
		cmd.WriteString(" " + lit(msg(10+i)))
	}
	// Session b polls while a appends: it must see nothing of the failed command.
	done := make(chan []string)
	go func() {
		var seen []string
		for n := 0; n < 30; n++ {
			tag := fmt.Sprintf("p%d", n)
			fmt.Fprintf(b, "%s NOOP\r\n", tag)
			for {
				line, err := rb.ReadString('\n')
				if err != nil {
					done <- append(seen, err.Error())
					return
				}
				if strings.HasPrefix(line, tag+" ") {
					break
				}
				seen = append(seen, line)
			}
		}
		done <- seen
	}()
	send(t, a, cmd.String())
	expectPrefix(t, ra, "a2 NO [OVERQUOTA]")
	if seen := <-done; len(seen) != 0 {
		t.Fatalf("another session saw a failed MULTIAPPEND: %q", seen)
	}
	if after := status(); after != before {
		t.Fatalf("failed MULTIAPPEND changed the mailbox: %q, was %q", after, before)
	}

	// A sync literal over quota is refused before the continuation, so it is never uploaded.
	limit = 2
	if err := inbox.SetQuotaLimits(ctx, accID, nil, &limit); err != nil {
		t.Fatal(err)
	}
	send(t, a, "a3 APPEND INBOX {20}")
	expectPrefix(t, ra, "a3 NO [OVERQUOTA]")
	send(t, a, "a4 NOOP")
	expectPrefix(t, ra, "a4 OK")

	// Malformed parameters end in BAD, not a loop (CVE-2013-2111, CVE-2006-6762, CVE-2021-40111).
	for i, arg := range []string{"(", "((", `(\Seen`, `"1-Jan-2000`, "{", "{x}", "CATENATE (", "CATENATE (TEXT", "INBOX ~{"} {
		send(t, a, fmt.Sprintf("b%d APPEND INBOX %s", i, arg))
		expectPrefix(t, ra, fmt.Sprintf("b%d BAD", i))
	}
}

// TestRFC3502AppendStreamsLiterals: an APPEND literal is streamed to the blob store as it arrives,
// so announcing a large one costs no memory (CVE-2024-34055 class). Not parallel, so the heap
// figure is this test's own.
func TestRFC3502AppendStreamsLiterals(t *testing.T) {
	_, _, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	var conns []net.Conn
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	const sessions, size = 8, 30 << 20
	chunk := strings.Repeat("x", 1<<20)
	for range sessions {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		r := bufio.NewReader(c)
		expectPrefix(t, r, "* OK")
		send(t, c, "l1 LOGIN alice@localhost beaver")
		expectPrefix(t, r, "l1 OK")
		// Announced, and half sent: the server holds neither in memory.
		fmt.Fprintf(c, "a1 APPEND INBOX {%d+}\r\nSubject: x\r\n\r\n", size)
		for sent := 0; sent < size/2; sent += len(chunk) {
			if _, err := c.Write([]byte(chunk)); err != nil {
				t.Fatal(err)
			}
		}
	}
	time.Sleep(300 * time.Millisecond)
	runtime.ReadMemStats(&m1)
	// Held in memory, 8 half-sent 30 MiB literals were 240 MiB.
	if grew := (int64(m1.HeapInuse) - int64(m0.HeapInuse)) >> 20; grew > 32 {
		t.Fatalf("%d sessions mid-APPEND grew the heap by %d MiB", sessions, grew)
	}

	// A client gone mid-literal leaves no temp file (CVE-2006-0449: APPEND, then disconnect).
	for _, c := range conns {
		_ = c.Close()
	}
	root := filepath.Dir(filepath.Dir(inbox.Blobs().Path([32]byte{})))
	deadline := time.Now().Add(5 * time.Second)
	for {
		left, _ := filepath.Glob(filepath.Join(root, "put-*"))
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("temp files left after the clients left: %v", left)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
