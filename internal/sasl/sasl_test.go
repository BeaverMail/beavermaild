package sasl

import (
	"encoding/base64"
	"errors"
	"testing"
)

// RFC 4954 4: BASE64 only, "=" is empty, characters outside the alphabet and inner padding are
// rejected. RFC 4616 2: three fields.
func TestDecode(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	if raw, err := DecodeResponse("="); err != nil || len(raw) != 0 {
		t.Fatalf(`"=": %q %v`, raw, err)
	}
	for _, bad := range []string{"", "!!!notbase64", "AAA=BBB", "=AAA", "\x00alice\x00pw", "QUJD RA=="} {
		if _, err := DecodeResponse(bad); !errors.Is(err, ErrBadBase64) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	raw, err := DecodeResponse(b64("bob\x00alice\x00pw"))
	if err != nil {
		t.Fatal(err)
	}
	if z, u, p, err := ParsePlain(raw); err != nil || z != "bob" || u != "alice" || p != "pw" {
		t.Fatalf("plain: %q %q %q %v", z, u, p, err)
	}
	for _, bad := range []string{"alice\x00pw", "\x00\x00pw", "a\x00b\x00c\x00d"} {
		if _, _, _, err := ParsePlain([]byte(bad)); !errors.Is(err, ErrBadPlain) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if AuthorizedAs("bob@example.org", "alice@example.org") || !AuthorizedAs("", "a") || !AuthorizedAs("A@x", "a@X") {
		t.Fatal("AuthorizedAs")
	}
}
