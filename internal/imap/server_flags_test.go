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
	if line := readLine(); !strings.HasPrefix(line, `* 1 FETCH (FLAGS (\Deleted)`) {
		t.Fatalf("store replace %q", line)
	}
	expectPrefix(t, read, "f6 OK")

	send(t, conn, `f7 STORE 1 FLAGS.SILENT (\Seen)`)
	expectPrefix(t, read, "f7 OK")

	// Replace also replaces keywords.
	send(t, conn, `f8 STORE 1 +FLAGS ($old)`)
	readLine()
	expectPrefix(t, read, "f8 OK")
	send(t, conn, `f9 STORE 1 FLAGS ($new)`)
	if line := readLine(); !strings.HasPrefix(line, `* 1 FETCH (FLAGS ($new)`) {
		t.Fatalf("store replace keywords %q", line)
	}
	expectPrefix(t, read, "f9 OK")
}
