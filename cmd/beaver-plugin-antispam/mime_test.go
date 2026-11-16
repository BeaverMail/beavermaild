package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/mimetree"
)

// The filter reads the same MIME tree IMAP shows clients (RFC 2045, 2046). Each case hid
// http://evil.example/x from the filter while a client could display it: depth past 8, part 301,
// a message/rfc822 attachment, a base64 body with a character outside the alphabet (RFC 2045 6.8:
// ignored), a UTF-16 text part (RFC 2049 2: converted), an unterminated multipart (RFC 2046 5.1.2),
// a Content-Type after a malformed header line, a charset WHATWG maps to "replacement", a <meta>
// charset whose escape sequences split a link (ESC ( B in ISO-2022-JP, removed by the client).
func TestFilterSeesWhatClientsShow(t *testing.T) {
	t.Parallel()
	for _, c := range mimeCases() {
		if c.name == "dupboundary" || c.name == "badct" || c.name == "dupcte" || c.name == "encodedmultipart" {
			continue // ambiguous: covered by TestAmbiguousMIMEIsBroken
		}
		m := parseMessage([]byte(c.raw))
		found := false
		for _, u := range m.urls {
			found = found || u.raw == "http://evil.example/x"
		}
		if !found {
			t.Errorf("%s: URL not seen", c.name)
		}
	}
}

// Headers each client may read its own way are reported, not guessed.
func TestAmbiguousMIMEIsBroken(t *testing.T) {
	t.Parallel()
	for _, c := range mimeCases() {
		switch c.name {
		case "dupboundary", "badct", "dupcte", "dupct", "junkheader", "encodedmultipart":
			expectSyms(t, runChecks([]byte(c.raw), checkMIMEParts), []string{"BROKEN_CONTENT_TYPE"}, nil)
		}
	}
}

// Past the tree's limits a part is opaque to the filter; that is scored, not silently skipped.
func TestMIMEParseLimit(t *testing.T) {
	t.Parallel()
	deep := nest(mimetree.MaxDepth+2, "Content-Type: text/plain\r\n\r\nleaf\r\n")
	expectSyms(t, runChecks([]byte("From: a@example.org\r\n"+deep), checkMIMEParts), []string{"MIME_PARSE_LIMIT"}, nil)
	expectSyms(t, runChecks([]byte("From: a@example.org\r\n"+nest(3, "Content-Type: text/plain\r\n\r\nleaf\r\n")), checkMIMEParts), nil, []string{"MIME_PARSE_LIMIT"})
}

func nest(depth int, inner string) string {
	s := inner
	for i := depth; i > 0; i-- {
		b := fmt.Sprintf("b%d", i)
		s = "Content-Type: multipart/mixed; boundary=" + b + "\r\n\r\n--" + b + "\r\n" + s + "\r\n--" + b + "--\r\n"
	}
	return s
}

func mimeCases() []struct{ name, raw string } {
	leaf := "Content-Type: text/plain\r\n\r\nvisit http://evil.example/x\r\n"
	many := "Content-Type: multipart/mixed; boundary=m\r\n\r\n" + strings.Repeat("--m\r\nContent-Type: text/plain\r\n\r\nfiller\r\n", 300) +
		"--m\r\n" + leaf + "--m--\r\n"
	b64 := base64.StdEncoding.EncodeToString([]byte("hello there friend, visit http://evil.example/x now"))
	var u16 []byte
	for _, r := range "visit http://evil.example/x" {
		u16 = append(u16, byte(r), 0)
	}
	h := "From: a@example.org\r\nTo: b@example.org\r\nSubject: s\r\nMIME-Version: 1.0\r\n"
	return []struct{ name, raw string }{
		{"depth9", h + nest(9, leaf)},
		{"300parts", h + many},
		{"rfc822", h + "Content-Type: multipart/mixed; boundary=z\r\n\r\n--z\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--z\r\nContent-Type: message/rfc822\r\n\r\nFrom: x@example.net\r\nSubject: inner\r\n\r\nvisit http://evil.example/x\r\n--z--\r\n"},
		{"b64junk", h + "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64[:8] + "!" + b64[8:] + "\r\n"},
		{"utf16", h + "Content-Type: text/plain; charset=utf-16le\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(u16) + "\r\n"},
		{"noclose", h + "Content-Type: multipart/mixed; boundary=q\r\n\r\n--q\r\nContent-Type: text/plain\r\n\r\nvisit http://evil.example/x\r\n"},
		{"junkheader", h + "Content-Type: multipart/mixed; boundary=o\r\n\r\n--o\r\nX-Junk line without colon\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64 + "\r\n--o--\r\n"},
		{"encodedmultipart", h + "Content-Type: multipart/mixed; boundary=z\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
			base64.StdEncoding.EncodeToString([]byte("--z\r\nContent-Type: text/plain\r\n\r\nvisit http://evil.example/x\r\n--z--\r\n")) + "\r\n"},
		{"iso2022kr", h + "Content-Type: text/plain; charset=iso-2022-kr\r\n\r\nvisit http://evil.example/x\r\n"},
		{"metacharset", h + "Content-Type: text/html\r\n\r\n<html><head><meta charset=\"iso-2022-jp\"></head><body><a href=\"http://evil.ex\x1b(Bample/x\">x</a> http://evil.ex\x1b(Bample/x</body></html>\r\n"},
		{"mixedends", "From: a@example.org\r\nSubject: s\r\n\nvisit http://evil.example/x\r\n\r\nrest\r\n"}, // body for the client, header for "\r\n\r\n first"
		{"dupboundary", h + "Content-Type: multipart/mixed; boundary=a; boundary=b\r\n\r\n--a\r\n\r\nclean\r\n--a--\r\n"},
		{"badct", h + "Content-Type: multipart/mixed; boundary=\"q\"x\r\n\r\n--q\r\n\r\nx\r\n--q--\r\n"},
		{"dupcte", h + "Content-Type: text/plain\r\nContent-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64 + "\r\n"},
		{"dupct", h + "Content-Type: text/plain\r\nContent-Type: text/html\r\n\r\n<a href=\"http://evil.example/x\">ok</a>\r\n"},
	}
}
