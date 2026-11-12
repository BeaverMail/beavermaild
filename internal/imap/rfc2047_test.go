package imap

import (
	"strings"
	"testing"
)

// RFC 2047 5: encoded-words only in a phrase (display name) or *text; never in an addr-spec, a
// quoted-string or a MIME parameter. In a phrase only letters, digits and ! * + - / = _ may
// appear, so names are B-encoded (Q left "," and "." bare). Parameters use RFC 2231.
func TestRFC2047EncodedWordPlacement(t *testing.T) {
	env := formatEnvelope([]byte("From: =?utf-8?b?Sm9zw6ksIEpyLg==?= <jose@example.org>\r\n" +
		"To: =?utf-8?q?attacker=40evil.example?=@example.org\r\n" +
		"Cc: =?utf-8?q?x?= <caf\xc3\xa9@example.org>\r\n\r\n"))
	for _, want := range []string{
		`(("=?utf-8?b?Sm9zw6ksIEpyLg==?=" NIL "jose" "example.org"))`,     // phrase: B-encoded
		`((NIL NIL "=?utf-8?q?attacker=40evil.example?=" "example.org"))`, // addr-spec: never decoded
		"{5}\r\ncaf\xc3\xa9", // 8-bit addr-spec: literal, not encoded
	} {
		if !strings.Contains(env, want) {
			t.Errorf("ENVELOPE lacks %q:\n%s", want, env)
		}
	}
	bs := formatBodyStructure([]byte("Content-Type: application/pdf; name*=UTF-8''r%C3%A9sum%C3%A9%20v1.pdf\r\n" +
		"Content-Description: r\xc3\xa9sum\xc3\xa9\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAA\r\n"))
	for _, want := range []string{
		`("NAME*" "utf-8''r%C3%A9sum%C3%A9%20v1.pdf")`, // parameter: RFC 2231 form
		`"=?utf-8?b?csOpc3Vtw6k=?="`,                   // raw 8-bit *text (RFC 6532): encoded-word
	} {
		if !strings.Contains(bs, want) {
			t.Errorf("BODYSTRUCTURE lacks %q:\n%s", want, bs)
		}
	}
	if strings.Contains(bs, `"NAME" "=?`) {
		t.Errorf("encoded-word in a parameter: %s", bs)
	}
}

// URLFETCH BINARY BODYPARTSTRUCTURE reports 0 lines for decoded data, as Dovecot does (imaptest
// urlauth-binary); the raw part keeps its count. Temporary: see .specs/dovecot.md.
func TestURLFetchDecodedPartLines(t *testing.T) {
	raw := []byte("Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\naGVsbG8K\r\nd29ybGQK\r\n--b--\r\n")
	dec, err := binarySection(raw, "1")
	if err != nil {
		t.Fatal(err)
	}
	if got := urlPartStructure(raw, "1", true, dec); !strings.Contains(got, `"7BIT" 12 0 `) {
		t.Fatalf("decoded: %s", got)
	}
	if got := urlPartStructure(raw, "1", false, nil); !strings.Contains(got, `"BASE64" 18 2 `) {
		t.Fatalf("raw: %s", got)
	}
}
