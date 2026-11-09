package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"testing"
)

// TestIMAPSearchCharsetSeqSetModSeq covers CHARSET with literals, RFC 2047 subjects,
// bare sequence sets, MODSEQ, and the charset of SORT/THREAD.
func TestIMAPSearchCharsetSeqSetModSeq(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	msgs := [][]byte{
		[]byte("From: alice@example.com\r\nSubject: =?UTF-8?Q?Gita_in_citt=C3=A0?=\r\n\r\nbody\r\n"),
		[]byte("From: bob@example.com\r\nSubject: plain\r\n\r\nbody\r\n"),
		[]byte("From: carol@example.com\r\nSubject: third\r\n\r\nbody\r\n"),
	}
	for _, raw := range msgs {
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
	send(t, conn, "c1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "c1 OK")
	send(t, conn, "c2 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 3 EXISTS")
	expectPrefix(t, read, "* 3 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "c2 OK")

	// Synchronizing literal: the server asks for the bytes with a continuation.
	needle := "città"
	send(t, conn, fmt.Sprintf("c3 SEARCH CHARSET UTF-8 SUBJECT {%d}", len(needle)))
	expectPrefix(t, read, "+ ")
	send(t, conn, needle)
	expectPrefix(t, read, "* SEARCH 1\r\n")
	expectPrefix(t, read, "c3 OK")

	// Non-synchronizing literal (LITERAL+) followed by more criteria.
	send(t, conn, fmt.Sprintf("c4 UID SEARCH CHARSET \"utf-8\" OR SUBJECT {%d+}", len(needle)))
	send(t, conn, needle+" FROM bob@example.com")
	expectPrefix(t, read, "* SEARCH 1 2\r\n")
	expectPrefix(t, read, "c4 OK")

	send(t, conn, "c5 SEARCH CHARSET ISO-2022-JP SUBJECT x")
	expectPrefix(t, read, "c5 NO [BADCHARSET (UTF-8 US-ASCII)]")

	send(t, conn, "c6 SEARCH 2:* NOT FROM carol@example.com")
	expectPrefix(t, read, "* SEARCH 2\r\n")
	expectPrefix(t, read, "c6 OK")

	send(t, conn, "c7 SEARCH 1,3")
	expectPrefix(t, read, "* SEARCH 1 3\r\n")
	expectPrefix(t, read, "c7 OK")

	send(t, conn, "c8 UID SEARCH UID 1,3:*")
	expectPrefix(t, read, "* SEARCH 1 3\r\n")
	expectPrefix(t, read, "c8 OK")

	send(t, conn, "c9 SEARCH MODSEQ 1")
	expectPrefix(t, read, "* SEARCH 1 2 3 (MODSEQ ")
	expectPrefix(t, read, "c9 OK")

	send(t, conn, `c10 SEARCH MODSEQ "/flags/\\Seen" all 1 FROM bob@example.com`)
	expectPrefix(t, read, "* SEARCH 2 (MODSEQ ")
	expectPrefix(t, read, "c10 OK")

	send(t, conn, "c11 SEARCH MODSEQ 18446744073")
	expectPrefix(t, read, "* SEARCH\r\n")
	expectPrefix(t, read, "c11 OK")

	send(t, conn, "c12 SORT (REVERSE ARRIVAL) UTF-8 OR (FROM alice@example.com) (FROM bob@example.com)")
	expectPrefix(t, read, "* SORT 2 1\r\n")
	expectPrefix(t, read, "c12 OK")

	send(t, conn, "c13 SORT (ARRIVAL) KOI8-R ALL")
	expectPrefix(t, read, "c13 NO [BADCHARSET")

	send(t, conn, "c14 UID THREAD REFERENCES US-ASCII 2:3")
	expectPrefix(t, read, "* THREAD (2)(3)\r\n")
	expectPrefix(t, read, "c14 OK")
}
