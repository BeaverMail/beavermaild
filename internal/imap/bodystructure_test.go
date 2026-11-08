package imap

import (
	"strings"
	"testing"
	"time"
)

func TestFormatBodyStructurePlain(t *testing.T) {
	t.Parallel()

	raw := []byte("From: a@b.com\r\nSubject: hi\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nhello\r\n")
	bs := formatBodyStructure(raw)
	if !strings.Contains(bs, `"TEXT" "PLAIN"`) || !strings.Contains(bs, "UTF-8") || !strings.Contains(bs, `"7BIT"`) {
		t.Fatalf("plain: %s", bs)
	}
}

func TestFormatBodyStructureMultipart(t *testing.T) {
	t.Parallel()

	raw := []byte("Content-Type: multipart/alternative; boundary=abc\r\n\r\n" +
		"--abc\r\nContent-Type: text/plain\r\n\r\nplain\r\n" +
		"--abc\r\nContent-Type: text/html\r\n\r\n<b>html</b>\r\n" +
		"--abc--\r\n")
	bs := formatBodyStructure(raw)
	if !strings.Contains(bs, `"ALTERNATIVE"`) || !strings.Contains(bs, `"HTML"`) {
		t.Fatalf("multipart: %s", bs)
	}
}

// RFC 3501 body-type-mpart: parts back to back (no SP between them), also when nested.
func TestFormatBodyStructureNestedMultipartNoSpaceBetweenParts(t *testing.T) {
	t.Parallel()

	raw := []byte("Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
		"--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n" +
		"--inner\r\nContent-Type: text/plain; charset=utf-8\r\n\r\ntest\r\n" +
		"--inner\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>test</p>\r\n" +
		"--inner--\r\n" +
		"--outer\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERg==\r\n" +
		"--outer--\r\n")
	want := `((("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 4 1)("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "7BIT" 11 1) "ALTERNATIVE" NIL)` +
		`("APPLICATION" "PDF" NIL NIL NIL "BASE64" 8) "MIXED" NIL)`
	if got := formatBodyStructure(raw); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// body-type-msg: message/rfc822 parts include the inner envelope, body structure and line count.
func TestFormatBodyStructureMessageRFC822(t *testing.T) {
	t.Parallel()

	inner := "Subject: inner\r\nFrom: bob@example.com\r\n\r\nhi\r\n"
	raw := []byte("Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n" +
		"--b\r\nContent-Type: message/rfc822\r\n\r\n" + inner +
		"--b--\r\n")
	bs := formatBodyStructure(raw)
	for _, want := range []string{`("MESSAGE" "RFC822" NIL NIL NIL "7BIT" `, ` "inner" `, `("TEXT" "PLAIN" NIL NIL NIL "7BIT" 2 1) 4)`} {
		if !strings.Contains(bs, want) {
			t.Fatalf("missing %q in %s", want, bs)
		}
	}
}

func TestFormatInternalDate(t *testing.T) {
	t.Parallel()

	day := time.Date(2024, 3, 15, 12, 30, 0, 0, time.UTC)
	got := formatInternalDate(day.Unix())
	want := `"15-Mar-2024 12:30:00 +0000"`
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestParseFetchBodyStructure(t *testing.T) {
	t.Parallel()

	_, items, ok := parseFetchArg(`1 (BODYSTRUCTURE INTERNALDATE UID)`)
	if !ok || !items.bodystructure || !items.internalDate || !items.uid {
		t.Fatalf("items %+v ok=%v", items, ok)
	}
}
