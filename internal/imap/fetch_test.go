package imap

import "testing"

func TestParseFetchItemsPeekBody(t *testing.T) {
	t.Parallel()

	_, items, ok := parseFetchArg(`1 (UID FLAGS RFC822.SIZE BODY.PEEK[])`)
	if !ok || !items.uid || !items.flags || !items.size || !items.body {
		t.Fatalf("peek in parens: ok=%v items=%+v", ok, items)
	}

	_, items, ok = parseFetchArg(`1 BODY.PEEK[]`)
	if !ok || !items.body || items.uid {
		t.Fatalf("bare peek: ok=%v items=%+v", ok, items)
	}

	_, items, ok = parseFetchArg(`1 (UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS (SUBJECT)])`)
	if !ok || !items.uid || items.body {
		t.Fatalf("header fields only: ok=%v items=%+v", ok, items)
	}
}

func TestWantsFullBody(t *testing.T) {
	t.Parallel()

	if !wantsFullBody("BODY.PEEK[]") {
		t.Fatal("peek full body")
	}
	if wantsFullBody("BODY.PEEK[HEADER.FIELDS (SUBJECT)]") {
		t.Fatal("header only")
	}
	if wantsFullBody("RFC822.SIZE") {
		t.Fatal("size only")
	}
}
