package smtp

import "testing"

func TestAddressNeedsUTF8(t *testing.T) {
	t.Parallel()
	if !addressNeedsUTF8("üser@example.com") {
		t.Fatal("expected utf8")
	}
	if addressNeedsUTF8("user@example.com") {
		t.Fatal("expected ascii")
	}
}

func TestValidEnvelopeAddress(t *testing.T) {
	t.Parallel()
	if !validEnvelopeAddress("alice@localhost") {
		t.Fatal("ascii ok")
	}
	if !validEnvelopeAddress("üser@example.com") {
		t.Fatal("utf8 ok")
	}
	if validEnvelopeAddress("bad") {
		t.Fatal("no @")
	}
	if validEnvelopeAddress("a@") {
		t.Fatal("no domain")
	}
}

func TestNormalizeEnvelopeAddress(t *testing.T) {
	t.Parallel()
	if got := normalizeEnvelopeAddress("Alice@Localhost"); got != "alice@localhost" {
		t.Fatalf("got %q", got)
	}
	utf8 := "Üser@example.com"
	if got := normalizeEnvelopeAddress(utf8); got != utf8 {
		t.Fatalf("got %q", got)
	}
}
