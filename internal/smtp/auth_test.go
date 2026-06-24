package smtp

import "testing"

func TestDecodeAuthPlain(t *testing.T) {
	t.Parallel()

	user, pass, ok := decodeAuthPlain("AGFsaWNlQGxvY2FsaG9zdABiZWF2ZXI=")
	if !ok || user != "alice@localhost" || pass != "beaver" {
		t.Fatalf("got %q %q ok=%v", user, pass, ok)
	}

	user, pass, ok = decodeAuthPlain("\x00alice@localhost\x00beaver")
	if !ok || user != "alice@localhost" || pass != "beaver" {
		t.Fatalf("raw got %q %q ok=%v", user, pass, ok)
	}

	if _, _, ok := decodeAuthPlain(""); ok {
		t.Fatal("empty")
	}
}
