package imap_test

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
)

// readResponse reads one response line including any literals it carries.
func readResponse(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(line)
		if !strings.HasSuffix(line, "}\r\n") {
			return b.String()
		}
		n, err := literalSize(strings.TrimSuffix(line, "\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			t.Fatal(err)
		}
		b.Write(buf)
	}
}

// TestIMAPFetch8BitStringsAsLiterals: decoded non-ASCII names and filenames must not be sent
// as quoted strings (7-bit only in IMAP4rev1).
func TestIMAPFetch8BitStringsAsLiterals(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := "From: =?UTF-8?Q?Jos=C3=A9?= <jose@example.com>\r\n" +
		"Subject: test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n" +
		"--b\r\nContent-Type: application/pdf; name*=UTF-8''fattura%C3%A0.pdf\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\nAAAA\r\n--b--\r\n"
	if _, err := inbox.Deliver(ctx, accID, []byte(raw)); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "e1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "e1 OK")
	send(t, conn, "e2 EXAMINE INBOX")
	for line := ""; !strings.HasPrefix(line, "e2 OK"); {
		line = readResponse(t, read)
	}

	send(t, conn, "e3 FETCH 1 (ENVELOPE BODYSTRUCTURE)")
	resp := readResponse(t, read)
	expectPrefix(t, read, "e3 OK")
	if !strings.Contains(resp, "(({5}\r\nJosé NIL \"jose\" \"example.com\"))") {
		t.Fatalf("envelope name not a literal: %q", resp)
	}
	if !strings.Contains(resp, "(\"NAME\" {13}\r\nfatturaà.pdf)") {
		t.Fatalf("filename not a literal: %q", resp)
	}
}

func TestIMAPFetchPartial(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	if _, err := inbox.Deliver(ctx, accID, []byte("Subject: p\r\n\r\n0123456789\r\n")); err != nil {
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
	send(t, conn, "p2 EXAMINE INBOX")
	for line := ""; !strings.HasPrefix(line, "p2 OK"); {
		line = readResponse(t, read)
	}

	send(t, conn, "p3 FETCH 1 (BODY.PEEK[TEXT]<2.4> BODY.PEEK[TEXT]<100.5>)")
	resp := readResponse(t, read)
	expectPrefix(t, read, "p3 OK")
	if want := "* 1 FETCH (BODY[TEXT]<2> {4}\r\n2345 BODY[TEXT]<100> {0}\r\n)\r\n"; resp != want {
		t.Fatalf("partial %q want %q", resp, want)
	}
}
