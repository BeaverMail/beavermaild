package imap

import (
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// TestUIDBatchesResend checks RFC 10022 3.1.1: the same request is refused until more than N/2
// messages were expunged or added; other batch ranges stay allowed.
func TestUIDBatchesResend(t *testing.T) {
	s := &session{}
	setUIDs := func(lo, hi uint32) {
		s.messages = s.messages[:0]
		for u := lo; u <= hi; u++ {
			s.messages = append(s.messages, mail.Message{UID: u})
		}
	}
	setUIDs(1, 1000)
	steps := []struct {
		name        string
		first, last int
		mutate      func()
		want        bool
	}{
		{"first request", 1, 2, nil, true},
		{"same request, no change", 1, 2, nil, false},
		{"overlapping page (3.1.5)", 2, 3, nil, true},
		{"250 new: not more than N/2", 1, 2, func() { setUIDs(1, 1250) }, false},
		{"251 new", 1, 2, func() { setUIDs(1, 1251) }, true},
		{"251 expunged", 1, 2, func() { setUIDs(252, 1251) }, true},
		{"250 expunged, 250 new", 1, 2, func() { setUIDs(502, 1501) }, false},
	}
	for _, st := range steps {
		if st.mutate != nil {
			st.mutate()
		}
		if got := s.allowUIDBatches(500, st.first, st.last); got != st.want {
			t.Fatalf("%s: allowed=%v, want %v", st.name, got, st.want)
		}
	}

	// The record is bounded: past uidBatchesTracked distinct requests, new ones are refused until
	// the mailbox changes.
	s.uidBatches = nil
	for i := 1; i <= uidBatchesTracked; i++ {
		if !s.allowUIDBatches(500, i, i) {
			t.Fatalf("distinct request %d refused", i)
		}
	}
	if s.allowUIDBatches(500, 1000, 1000) {
		t.Fatal("request past the bound allowed")
	}
	setUIDs(502, 2001)
	if !s.allowUIDBatches(500, 1000, 1000) {
		t.Fatal("refused after the mailbox changed")
	}
}

// TestParseNZNumber checks the nz-number grammar: 32 bits, no sign, no leading zero.
func TestParseNZNumber(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "4294967295": true, "4294967296": false, "0": false, "01": false, "+1": false, "-1": false, "": false} {
		if _, ok := parseNZNumber(v); ok != want {
			t.Errorf("%q: ok=%v, want %v", v, ok, want)
		}
	}
}

// TestIMAPURLUIDRange: a UID past 32 bits is refused, not truncated to another message (4294967297
// was read as UID 1).
func TestIMAPURLUIDRange(t *testing.T) {
	for _, raw := range []string{"/INBOX/;UID=4294967297", "/INBOX;UIDVALIDITY=4294967296/;UID=1"} {
		if u, ok := parseIMAPURL(raw); ok {
			t.Errorf("%q parsed as uid %d", raw, u.uid)
		}
	}
}
