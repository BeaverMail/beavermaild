package imap_test

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"
)

// TestIMAPFlagsCaseAndStoreReplace checks that system flags are case-insensitive (APPEND with
// \seen) and that STORE FLAGS (replace, not .SILENT) answers with an untagged FETCH.
func TestIMAPFlagsCaseAndStoreReplace(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	readLine := func() string {
		t.Helper()
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return line
	}
	expectPrefix(t, read, "* OK")
	send(t, conn, "f1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "f1 OK")
	send(t, conn, "f2 CREATE Flags")
	expectPrefix(t, read, "f2 OK")
	msg := "Subject: x\r\n\r\nx\r\n"
	send(t, conn, `f3 APPEND Flags (\seen \FLAGGED) {`+strconv.Itoa(len(msg))+"+}\r\n"+msg[:len(msg)-2])
	expectPrefix(t, read, "f3 OK")
	send(t, conn, "f4 SELECT Flags")
	for line := ""; !strings.HasPrefix(line, "f4 OK"); {
		line = readLine()
	}

	send(t, conn, "f5 FETCH 1 (FLAGS)")
	if line := readLine(); !strings.Contains(line, `\Seen`) || !strings.Contains(line, `\Flagged`) {
		t.Fatalf("append flags %q", line)
	}
	expectPrefix(t, read, "f5 OK")

	send(t, conn, `f6 STORE 1 FLAGS \deleted`)
	// APPENDed before SELECT, so \Recent for this session.
	if line := readLine(); !strings.HasPrefix(line, `* 1 FETCH (FLAGS (\Deleted \Recent)`) {
		t.Fatalf("store replace %q", line)
	}
	expectPrefix(t, read, "f6 OK")

	send(t, conn, `f7 STORE 1 FLAGS.SILENT (\Seen)`)
	expectPrefix(t, read, "f7 OK")

	// Replace also replaces keywords.
	send(t, conn, `f8 STORE 1 +FLAGS ($old)`)
	// A keyword new to the mailbox is announced before the FETCH that uses it.
	expectPrefix(t, read, `* FLAGS (\Answered \Flagged \Deleted \Seen \Draft $old)`)
	expectPrefix(t, read, `* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft $old \*)]`)
	readLine()
	expectPrefix(t, read, "f8 OK")
	send(t, conn, `f9 STORE 1 FLAGS ($new)`)
	expectPrefix(t, read, `* FLAGS (\Answered \Flagged \Deleted \Seen \Draft $new $old)`)
	expectPrefix(t, read, "* OK [PERMANENTFLAGS")
	if line := readLine(); !strings.HasPrefix(line, `* 1 FETCH (FLAGS (\Recent $new)`) {
		t.Fatalf("store replace keywords %q", line)
	}
	expectPrefix(t, read, "f9 OK")
}

// TestIMAPRecentSession follows imaptest select/search-flags: EXAMINE keeps \Recent; SELECT takes
// it for the selecting session, which keeps reporting it, while other sessions see none.
func TestIMAPRecentSession(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	for range 2 {
		if _, err := inbox.Deliver(ctx, accID, []byte("Subject: r\r\n\r\nx\r\n")); err != nil {
			t.Fatal(err)
		}
	}

	dial := func(tag string) (net.Conn, *bufio.Reader) {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		read := bufio.NewReader(conn)
		expectPrefix(t, read, "* OK")
		send(t, conn, tag+" LOGIN alice@localhost beaver")
		expectPrefix(t, read, tag+" OK")
		return conn, read
	}
	conn, read := dial("r0")
	cmd := func(line string) string {
		t.Helper()
		send(t, conn, line)
		tag, _, _ := strings.Cut(line, " ")
		var out string
		for {
			l, err := read.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(l, tag+" ") {
				if !strings.HasPrefix(l, tag+" OK") {
					t.Fatalf("%s: %q", line, l)
				}
				return out
			}
			out += l
		}
	}

	if got := cmd("r1 EXAMINE INBOX"); !strings.Contains(got, "* 2 RECENT") {
		t.Fatalf("examine %q", got)
	}
	cmd("r2 CLOSE")
	if got := cmd("r3 STATUS INBOX (RECENT)"); !strings.Contains(got, "RECENT 2") {
		t.Fatalf("status after examine %q", got)
	}
	if got := cmd("r4 SELECT INBOX"); !strings.Contains(got, "* 2 RECENT") {
		t.Fatalf("select %q", got)
	}
	if got := cmd("r5 SEARCH RECENT"); got != "* SEARCH 1 2\r\n" {
		t.Fatalf("search recent %q", got)
	}
	if got := cmd(`r6 STORE 1 FLAGS (\Seen)`); !strings.Contains(got, `\Recent`) || !strings.Contains(got, `\Seen`) {
		t.Fatalf("store keeps recent %q", got)
	}

	other, otherRead := dial("o0")
	send(t, other, "o1 STATUS INBOX (RECENT)")
	expectPrefix(t, otherRead, "* STATUS INBOX (RECENT 0)")
	expectPrefix(t, otherRead, "o1 OK")
}
