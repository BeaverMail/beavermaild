package mimetree

import (
	"fmt"
	"strings"
	"testing"
)

func TestStructure(t *testing.T) {
	t.Parallel()
	raw := "Content-Type: multipart/mixed; boundary=b\r\n\r\npreamble\r\n--b\r\nContent-Type: text/plain\r\n\r\none\r\n" +
		"--b\r\nContent-Type: message/rfc822\r\n\r\nSubject: inner\r\n\r\ntwo\r\n--b--\r\nepilogue\r\n"
	p := Parse([]byte(raw))
	if p.Type != "multipart/mixed" || len(p.Children) != 2 {
		t.Fatalf("root %s with %d children", p.Type, len(p.Children))
	}
	if got := string(p.Children[0].Body); got != "one" {
		t.Errorf("part 1 body %q", got)
	}
	msg := p.Children[1]
	if msg.Type != "message/rfc822" || len(msg.Children) != 1 || string(msg.Children[0].Body) != "two" || msg.Children[0].Depth != 2 {
		t.Errorf("encapsulated message: %+v", msg)
	}
}

// RFC 2046 5.1.2: an improperly truncated multipart has no close delimiter; its content is kept,
// and an outer delimiter still ends it.
func TestUnterminatedMultipart(t *testing.T) {
	t.Parallel()
	p := Parse([]byte("Content-Type: multipart/mixed; boundary=q\r\n\r\n--q\r\n\r\nlast words\r\n"))
	if len(p.Children) != 1 || string(p.Children[0].Body) != "last words\r\n" {
		t.Fatalf("children %d", len(p.Children))
	}
	outer := "Content-Type: multipart/mixed; boundary=o\r\n\r\n--o\r\nContent-Type: multipart/mixed; boundary=i\r\n\r\n" +
		"--i\r\n\r\ninner\r\n--o\r\n\r\nafter\r\n--o--\r\n"
	p = Parse([]byte(outer))
	if len(p.Children) != 2 || string(p.Children[0].Children[0].Body) != "inner" || string(p.Children[1].Body) != "after" {
		t.Fatalf("outer delimiter must end the inner multipart: %d children", len(p.Children))
	}
}

// RFC 2046 5.1.5: in a digest a part with no Content-Type is a message/rfc822.
func TestDigestDefault(t *testing.T) {
	t.Parallel()
	p := Parse([]byte("Content-Type: multipart/digest; boundary=d\r\n\r\n--d\r\n\r\nSubject: x\r\n\r\nbody\r\n--d--\r\n"))
	if c := p.Children[0]; c.Type != "message/rfc822" || len(c.Children) != 1 {
		t.Fatalf("digest child %s", c.Type)
	}
}

// RFC 2045 5.2: an invalid Content-Type is text/plain, and is reported.
func TestBadType(t *testing.T) {
	t.Parallel()
	p := Parse([]byte("Content-Type: multipart/mixed; boundary=a; boundary=b\r\n\r\n--a\r\n\r\nx\r\n--a--\r\n"))
	if p.Type != "text/plain" || !p.BadType {
		t.Fatalf("type %s bad %v", p.Type, p.BadType)
	}
}

func nested(depth int) string {
	s := "Content-Type: text/plain\r\n\r\nleaf\r\n"
	for i := depth; i > 0; i-- {
		b := fmt.Sprintf("b%d", i)
		s = "Content-Type: multipart/mixed; boundary=" + b + "\r\n\r\n--" + b + "\r\n" + s + "\r\n--" + b + "--\r\n"
	}
	return s
}

func TestDepthLimit(t *testing.T) {
	t.Parallel()
	p := Parse([]byte(nested(MaxDepth + 5)))
	depth := 0
	for len(p.Children) > 0 {
		p, depth = p.Children[0], depth+1
	}
	if depth != MaxDepth || !p.Opaque || p.Type != "application/octet-stream" {
		t.Fatalf("stopped at %d, opaque %v, type %s", depth, p.Opaque, p.Type)
	}
}

func count(p *Part) int {
	n := 1
	for _, c := range p.Children {
		n += count(c)
	}
	return n
}

// 32 MiB of empty parts is millions of them; the tree keeps MaxParts, and the rest stays in the
// last part, so no byte is lost.
func TestPartLimit(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("Content-Type: multipart/mixed; boundary=m\r\n\r\n")
	for range MaxParts + 500 {
		b.WriteString("--m\r\n\r\nx\r\n")
	}
	b.WriteString("--m--\r\n")
	p := Parse([]byte(b.String()))
	if n := count(p); n != MaxParts {
		t.Fatalf("%d parts", n)
	}
	last := p.Children[len(p.Children)-1]
	if !p.Truncated || !strings.HasSuffix(string(last.Body), "--m--\r\n") {
		t.Fatalf("truncated %v, last part ends %q", p.Truncated, last.Body[max(0, len(last.Body)-20):])
	}
}

// CVE-2020-25275: Dovecot's part limit crashed when the part at the limit was a message/rfc822.
// Here it is an opaque leaf, as is every part past the limit.
func TestPartLimitAtMessage(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("Content-Type: multipart/mixed; boundary=m\r\n\r\n")
	for range MaxParts - 2 {
		b.WriteString("--m\r\n\r\nx\r\n")
	}
	b.WriteString("--m\r\nContent-Type: message/rfc822\r\n\r\nContent-Type: multipart/mixed; boundary=n\r\n\r\n--n\r\n\r\ny\r\n--n--\r\n--m--\r\n")
	p := Parse([]byte(b.String()))
	last := p.Children[len(p.Children)-1]
	if count(p) != MaxParts || !last.Opaque || last.Children != nil {
		t.Fatalf("%d parts, last %s opaque %v", count(p), last.Type, last.Opaque)
	}
}

func TestDecode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ cte, in, want string }{
		{"base64", "aGVs!bG8g\r\nd29y bGQ=", "hello world"}, // RFC 2045 6.8: outside the alphabet is ignored
		{"BASE64", "aGVsbG8", "hello"},
		{"quoted-printable", "a=3Db=\r\nc\x01", "a=bc\x01"},
		{"7bit", "as is", "as is"},
	} {
		got, ok := Decode(tc.cte, []byte(tc.in))
		if !ok || string(got) != tc.want {
			t.Errorf("%s %q: %q %v", tc.cte, tc.in, got, ok)
		}
	}
	if _, ok := Decode("x-uuencode", []byte("x")); ok {
		t.Error("unknown encoding decoded")
	}
}

// A malformed header line is skipped and reported: net/textproto stopped there, and the
// Content-Type after it was lost while a lenient client used it.
func TestLenientHeader(t *testing.T) {
	t.Parallel()
	p := Parse([]byte("X-Junk line without colon\r\nContent-Type: text/html;\r\n charset=utf-8\r\nSubject : obs\r\n\r\nbody"))
	if p.Type != "text/html" || p.Params["charset"] != "utf-8" || !p.BadHeader {
		t.Fatalf("type %s params %v bad %v", p.Type, p.Params, p.BadHeader)
	}
	if got := p.MIME.Get("Subject"); got != "obs" {
		t.Fatalf("obsolete field name: %q", got)
	}
	if p := Parse([]byte("Content-Type: text/plain\r\n\r\nx")); p.BadHeader {
		t.Fatal("clean header reported bad")
	}
	if p := Parse([]byte(" leading continuation\r\nContent-Type: text/html\r\n\r\nx")); p.Type != "text/html" || !p.BadHeader {
		t.Fatalf("leading continuation: %s %v", p.Type, p.BadHeader)
	}
}

// RFC 2045 6.4: a composite type takes no encoding but 7bit, 8bit or binary.
func TestBadEncoding(t *testing.T) {
	t.Parallel()
	if p := Parse([]byte("Content-Type: multipart/mixed; boundary=z\r\nContent-Transfer-Encoding: base64\r\n\r\nLS16\r\n")); !p.BadEncoding {
		t.Fatal("encoded multipart not reported")
	}
	if p := Parse([]byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGk=\r\n")); p.BadEncoding {
		t.Fatal("encoded leaf reported")
	}
}

// The header ends at the first empty line, CRLF or bare LF: BDAT stores mixed line ends as
// received, and IMAP clients see every bare LF as CRLF.
func TestHeaderEndMixedLineEnds(t *testing.T) {
	t.Parallel()
	for raw, body := range map[string]string{
		"Subject: x\n\nContent-Type: text/html\r\n\r\nbody": "Content-Type: text/html\r\n\r\nbody",
		"Subject: x\n\r\nrest\r\n\r\nmore":                  "rest\r\n\r\nmore",
		"Subject: x\r\n\nbody":                              "body",
		"Subject: x\r\n\r\nbody":                            "body",
		"\r\nbody":                                          "body",
		"Subject: x":                                        "",
	} {
		p := Parse([]byte(raw))
		if string(p.Body) != body {
			t.Errorf("%q: body %q, want %q", raw, p.Body, body)
		}
		if body != "" && p.MIME.Get("Content-Type") != "" {
			t.Errorf("%q: a body line read as a header field", raw)
		}
	}
}
