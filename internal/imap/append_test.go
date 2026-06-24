package imap

import "testing"

func TestParseAppendArg(t *testing.T) {
	t.Parallel()

	mbox, flags, size, ok := parseAppendArg(`Drafts (\Draft) {120}`)
	if !ok || mbox != "Drafts" || size != 120 || flags == 0 {
		t.Fatalf("draft: mbox=%q flags=%#x size=%d ok=%v", mbox, flags, size, ok)
	}

	mbox, flags, size, ok = parseAppendArg(`Drafts (NonJunk) {575}`)
	if !ok || mbox != "Drafts" || size != 575 || flags != 0 {
		t.Fatalf("nonjunk: mbox=%q flags=%#x size=%d ok=%v", mbox, flags, size, ok)
	}

	_, _, _, ok = parseAppendArg(`Drafts (\Draft) {bad}`)
	if ok {
		t.Fatal("bad literal size")
	}
}

func TestParseAppendFlags(t *testing.T) {
	t.Parallel()

	flags := parseAppendFlags(`(\Seen \Draft)`)
	if flags == 0 {
		t.Fatal("expected flags")
	}
	if parseAppendFlags(`(NonJunk)`) != 0 {
		t.Fatal("unknown flag ignored")
	}
}
