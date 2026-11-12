package imap_test

import (
	"io"
	"strconv"
	"strings"
	"testing"
)

// Messages arrive by SMTP DATA with LF line ends and are stored so (like Dovecot's default);
// IMAP serves them with CRLF line ends (RFC 3501 2.3.4): RFC822.SIZE, every literal length, the
// streamed full and partial bodies and the parsed sections all count the CRLF form.
func TestFetchLFStoredMessageAsCRLF(t *testing.T) {
	t.Parallel()
	ctx, acc, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	raw := "Subject: lf\nX-A: b\n\nline one\nline two\nline three\n"
	if _, err := inbox.Deliver(ctx, acc, []byte(raw)); err != nil {
		t.Fatal(err)
	}
	wire := strings.ReplaceAll(raw, "\n", "\r\n")

	lc := dialLiteral(t, ln.Addr().String())
	lc.write("l1 LOGIN alice@localhost beaver\r\n")
	lc.line("l1 OK")
	lc.write("s1 EXAMINE INBOX\r\n")
	lc.until("s1")

	// fetchLiteral sends a FETCH of one literal item and returns the head line and the literal.
	fetchLiteral := func(item string) (string, string) {
		lc.write("f1 FETCH 1 (" + item + ")\r\n")
		head := lc.line("* 1 FETCH")
		i := strings.LastIndexByte(head, '{')
		n, err := strconv.Atoi(strings.TrimSuffix(head[i+1:], "}\r\n"))
		if err != nil {
			t.Fatalf("%s: %q", item, head)
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(lc.r, data); err != nil {
			t.Fatal(err)
		}
		if rest := lc.line(")"); rest != ")\r\n" {
			t.Fatalf("%s: literal length off, then %q", item, rest)
		}
		lc.until("f1")
		return head, string(data)
	}
	head, body := fetchLiteral("RFC822.SIZE BODY.PEEK[]")
	if body != wire || !strings.Contains(head, "RFC822.SIZE "+strconv.Itoa(len(wire))+" ") {
		t.Fatalf("BODY[] %q (head %q), want %q", body, head, wire)
	}
	if _, part := fetchLiteral("BODY.PEEK[]<20.15>"); part != wire[20:35] {
		t.Fatalf("partial %q, want %q", part, wire[20:35])
	}
	if _, text := fetchLiteral("BODY.PEEK[TEXT]"); text != "line one\r\nline two\r\nline three\r\n" {
		t.Fatalf("TEXT %q", text)
	}
	lc.write("b1 FETCH 1 BODYSTRUCTURE\r\n")
	if bs := lc.line("* 1 FETCH"); !strings.Contains(bs, `"7BIT" 32 3`) {
		t.Fatalf("BODYSTRUCTURE counts the stored form: %q", bs)
	}
	lc.until("b1")
	lc.write("z1 SEARCH LARGER " + strconv.Itoa(len(wire)-1) + "\r\n")
	if res := lc.line("* SEARCH"); res != "* SEARCH 1\r\n" {
		t.Fatalf("LARGER uses the stored size: %q", res)
	}
}
