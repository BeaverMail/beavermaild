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

	addr, size, ok = parseMailArg("FROM:<a@b> RET=FULL ENVID=abc123 SIZE=10")
	if !ok || addr != "a@b" || size != 10 {
		t.Fatalf("dsn params: %q %d ok=%v", addr, size, ok)
	}

	addr, ok = parseRcptArg("TO:<bob@localhost> NOTIFY=FAILURE ORCPT=rfc822;bob@localhost")
	if !ok || addr != "bob@localhost" {
		t.Fatalf("rcpt dsn: %q ok=%v", addr, ok)
	}
	if _, ok := parseRcptArg("TO:<bad"); ok {
		t.Fatal("bad rcpt")
	}

	sizeChunk, last, ok := parseBDAT("100 LAST")
	if !ok || sizeChunk != 100 || !last {
		t.Fatalf("bdat last: %d last=%v ok=%v", sizeChunk, last, ok)
	}
	sizeChunk, last, ok = parseBDAT("50")
	if !ok || sizeChunk != 50 || last {
		t.Fatalf("bdat cont: %d last=%v ok=%v", sizeChunk, last, ok)
	}
	if _, _, ok := parseBDAT("x LAST"); ok {
		t.Fatal("bad bdat")
	}
}
