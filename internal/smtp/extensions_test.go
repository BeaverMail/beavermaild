package smtp

import "testing"

func TestParseMailArg(t *testing.T) {
	t.Parallel()

	addr, size, ok := parseMailArg("FROM:<alice@localhost>")
	if !ok || addr != "alice@localhost" || size != 0 {
		t.Fatalf("got %q %d ok=%v", addr, size, ok)
	}

	addr, size, ok = parseMailArg("FROM:<alice@localhost> SIZE=1024 BODY=8BITMIME")
	if !ok || addr != "alice@localhost" || size != 1024 {
		t.Fatalf("got %q %d ok=%v", addr, size, ok)
	}

	if _, _, ok := parseMailArg("FROM:<bad"); ok {
		t.Fatal("bad syntax")
	}
	if _, _, ok := parseMailArg("FROM:<a@b> SIZE=xy"); ok {
		t.Fatal("bad size")
	}
}
