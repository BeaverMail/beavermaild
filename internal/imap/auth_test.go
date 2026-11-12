package imap

import (
	"encoding/base64"
	"testing"
)

// PLAIN is base64 of [authzid] NUL authcid NUL passwd (RFC 3501 6.2.2, RFC 4616 2): a raw or
// two-field response, accepted before, is malformed.
func TestDecodeAuthPlain(t *testing.T) {
	t.Parallel()
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	authzid, user, pass, ok := decodeAuthPlain(b64("\x00alice@localhost\x00beaver"))
	if !ok || authzid != "" || user != "alice@localhost" || pass != "beaver" {
		t.Fatalf("plain: %q %q %q %v", authzid, user, pass, ok)
	}
	if authzid, _, _, ok = decodeAuthPlain(b64("bob@localhost\x00alice@localhost\x00beaver")); !ok || authzid != "bob@localhost" {
		t.Fatalf("authzid: %q %v", authzid, ok)
	}
	for _, bad := range []string{"", "\x00alice@localhost\x00beaver", "!!!notbase64", b64("alice@localhost\x00beaver"), b64("\x00\x00beaver"), "*"} {
		if _, _, _, ok := decodeAuthPlain(bad); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
}
