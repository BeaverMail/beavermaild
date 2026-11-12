package imap

import (
	"testing"
	"time"
)

func TestParseAppendArg(t *testing.T) {
	t.Parallel()

	mbox, flags, internalDate, size, nonsync, ok := parseAppendArg(`Drafts (\Draft) {120}`)
	if !ok || mbox != "Drafts" || size != 120 || flags == 0 || nonsync || internalDate != 0 {
		t.Fatalf("draft: mbox=%q flags=%#x size=%d date=%d nonsync=%v ok=%v", mbox, flags, size, internalDate, nonsync, ok)
	}

	mbox, flags, internalDate, size, nonsync, ok = parseAppendArg(`Drafts (NonJunk) {575}`)
	if !ok || mbox != "Drafts" || size != 575 || flags != 0 || nonsync || internalDate != 0 {
		t.Fatalf("nonjunk: mbox=%q flags=%#x size=%d date=%d nonsync=%v ok=%v", mbox, flags, size, internalDate, nonsync, ok)
	}

	mbox, _, internalDate, size, nonsync, ok = parseAppendArg(`Drafts {42+}`)
	if !ok || mbox != "Drafts" || size != 42 || !nonsync || internalDate != 0 {
		t.Fatalf("literal+: mbox=%q size=%d date=%d nonsync=%v ok=%v", mbox, size, internalDate, nonsync, ok)
	}

	_, _, internalDate, size, _, ok = parseAppendArg(`Drafts "02-Jan-2006 15:04:05 +0000" {42}`)
	if !ok || size != 42 || internalDate != time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC).Unix() {
		t.Fatalf("internal date: size=%d date=%d ok=%v", size, internalDate, ok)
	}

	_, flags, internalDate, size, _, ok = parseAppendArg(`Drafts (\Seen) "25-Jun-2024 10:30:00 -0500" {10}`)
	if !ok || size != 10 || flags == 0 || internalDate == 0 {
		t.Fatalf("flags+date: flags=%#x size=%d date=%d ok=%v", flags, size, internalDate, ok)
	}

	_, _, _, _, _, ok = parseAppendArg(`Drafts (\Draft) {bad}`)
	if ok {
		t.Fatal("bad literal size")
	}

	_, _, _, _, _, ok = parseAppendArg(`Drafts "not-a-date" {10}`)
	if ok {
		t.Fatal("bad internal date")
	}
}

// APPEND takes the same flag list as STORE: system flags, keywords, nothing malformed.
func TestParseAppendFlags(t *testing.T) {
	t.Parallel()

	spec, _, ok := parseAppendHead(`(\Seen \Draft $Label NonJunk Seen) {3}`)
	if !ok || spec.flags == 0 || len(spec.keywords) != 3 {
		t.Fatalf("flags %b keywords %q ok %v", spec.flags, spec.keywords, ok)
	}
	if _, _, ok := parseAppendHead(`(\Bogus) {3}`); ok {
		t.Fatal("unknown system flag accepted")
	}
	if spec, _, ok := parseAppendHead(`" 5-Nov-2026 10:00:00 +0000" {3}`); !ok || spec.internalDate == 0 {
		t.Fatal("space-padded day refused (RFC 3501 9 date-day-fixed)")
	}
	if spec, _, ok := parseAppendHead(`{0}`); !ok || spec.size != 0 {
		t.Fatal("{0} is a valid literal")
	}
}

func TestParseIMAPInternalDate(t *testing.T) {
	t.Parallel()

	tm, ok := parseIMAPInternalDate("02-Jan-2006 15:04:05 +0000")
	if !ok || tm.UTC() != time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC) {
		t.Fatalf("utc %v ok=%v", tm, ok)
	}
	if _, ok := parseIMAPInternalDate(""); ok {
		t.Fatal("empty date")
	}
}
