package imap

import (
	"strings"
	"testing"
)

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
	if !ok || !items.uid || items.body || items.headerFields == nil {
		t.Fatalf("header fields only: ok=%v items=%+v", ok, items)
	}
	if len(items.headerFields) != 1 || items.headerFields[0] != "SUBJECT" {
		t.Fatalf("fields %v", items.headerFields)
	}

	_, items, ok = parseFetchArg(`1 (UID FLAGS RFC822.SIZE ENVELOPE)`)
	if !ok || !items.envelope || !items.uid {
		t.Fatalf("envelope: ok=%v items=%+v", ok, items)
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

func TestExtractHeaderFields(t *testing.T) {
	t.Parallel()

	raw := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: hello\r\n\r\nbody\r\n")
	got := string(extractHeaderFields(raw, []string{"SUBJECT", "FROM"}))
	if !strings.Contains(got, "Subject: hello") || !strings.Contains(got, "From: a@b.com") {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(got, "To:") {
		t.Fatalf("unexpected To in %q", got)
	}
}

func TestFormatEnvelope(t *testing.T) {
	t.Parallel()

	raw := []byte("From: Alice <alice@example.com>\r\nTo: bob@example.com\r\nSubject: hi\r\nDate: Wed, 1 Jan 2025 00:00:00 +0000\r\nMessage-ID: <1@test>\r\n\r\n")
	env := formatEnvelope(raw)
	if !strings.Contains(env, `"hi"`) || !strings.Contains(env, "alice") || !strings.Contains(env, "bob") {
		t.Fatalf("env %s", env)
	}
}
