package imap

import "testing"

func TestParseAppendArg(t *testing.T) {
	t.Parallel()

	mbox, flags, size, nonsync, ok := parseAppendArg(`Drafts (\Draft) {120}`)
	if !ok || mbox != "Drafts" || size != 120 || flags == 0 || nonsync {
		t.Fatalf("draft: mbox=%q flags=%#x size=%d nonsync=%v ok=%v", mbox, flags, size, nonsync, ok)
	}

	mbox, flags, size, nonsync, ok = parseAppendArg(`Drafts (NonJunk) {575}`)
	if !ok || mbox != "Drafts" || size != 575 || flags != 0 || nonsync {
		t.Fatalf("nonjunk: mbox=%q flags=%#x size=%d nonsync=%v ok=%v", mbox, flags, size, nonsync, ok)
	}

	mbox, _, size, nonsync, ok = parseAppendArg(`Drafts {42+}`)
	if !ok || mbox != "Drafts" || size != 42 || !nonsync {
		t.Fatalf("literal+: mbox=%q size=%d nonsync=%v ok=%v", mbox, size, nonsync, ok)
	}

	_, _, _, _, ok = parseAppendArg(`Drafts (\Draft) {bad}`)
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
