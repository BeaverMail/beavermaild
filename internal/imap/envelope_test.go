package imap

import (
	"strings"
	"testing"
)

func TestFormatEnvelopeComplete(t *testing.T) {
	t.Parallel()

	raw := []byte("Date: Wed, 1 Jan 2025 12:00:00 +0000\r\n" +
		"From: Alice <alice@example.com>\r\n" +
		"Sender: Bob <bob@example.com>\r\n" +
		"Reply-To: Carol <carol@example.com>\r\n" +
		"To: dave@example.com, Eve <eve@example.org>\r\n" +
		"Cc: cc@example.net\r\n" +
		"Bcc: hidden@example.com\r\n" +
		"Subject: say \"hello\"\r\n" +
		"In-Reply-To: <parent@example.com>\r\n" +
		"Message-ID: <msg-1@example.com>\r\n\r\nbody\r\n")
	env := formatEnvelope(raw)

	checks := []string{
		`"Wed, 1 Jan 2025 12:00:00 +0000"`,
		`say \"hello\"`,
		`"Alice" NIL "alice" "example.com"`,
		`"Bob" NIL "bob" "example.com"`,
		`"Carol" NIL "carol" "example.com"`,
		`(NIL NIL "dave" "example.com")`,
		`"Eve" NIL "eve" "example.org"`,
		`(NIL NIL "cc" "example.net")`,
		`(NIL NIL "hidden" "example.com")`,
		`"<parent@example.com>"`,
		`"<msg-1@example.com>"`,
	}
	for _, want := range checks {
		if !strings.Contains(env, want) {
			t.Fatalf("missing %q in %s", want, env)
		}
	}
}

func TestFormatEnvelopeSenderReplyDefaults(t *testing.T) {
	t.Parallel()

	raw := []byte("From: Alice <alice@example.com>\r\nTo: bob@example.com\r\nSubject: hi\r\n\r\n")
	env := formatEnvelope(raw)
	if strings.Count(env, `"alice" "example.com"`) < 3 {
		t.Fatalf("sender/reply should default to from: %s", env)
	}
}

func TestFormatEnvelopeMissingFrom(t *testing.T) {
	t.Parallel()

	raw := []byte("To: bob@example.com\r\nSubject: hi\r\n\r\n")
	env := formatEnvelope(raw)
	if !strings.Contains(env, "NIL NIL NIL") {
		t.Fatalf("missing from nil: %s", env)
	}
}

func TestFormatEnvelopeMalformed(t *testing.T) {
	t.Parallel()

	if formatEnvelope([]byte("not a message")) != envelopeNIL() {
		t.Fatal("malformed should be all NIL")
	}
}

func TestQuoteIMAPStringEscapes(t *testing.T) {
	t.Parallel()

	got := quoteIMAPString(`a\b"c`)
	if got != `"a\\b\"c"` {
		t.Fatalf("quote %q", got)
	}
}
