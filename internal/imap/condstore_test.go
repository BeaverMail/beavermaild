package imap

import (
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

func TestParseUnchangedSince(t *testing.T) {
	t.Parallel()

	us, rest, ok := parseUnchangedSince("(UNCHANGEDSINCE 42) +FLAGS (\\Seen)")
	if !ok || us != 42 || rest != "+FLAGS (\\Seen)" {
		t.Fatalf("leading: us=%d rest=%q ok=%v", us, rest, ok)
	}
	us, rest, ok = parseTrailingUnchangedSince(`+FLAGS (\Seen) (UNCHANGEDSINCE 99)`)
	if !ok || us != 99 || rest != `+FLAGS (\Seen)` {
		t.Fatalf("trailing: us=%d rest=%q ok=%v", us, rest, ok)
	}
}

func TestParseStoreArgUnchangedSince(t *testing.T) {
	t.Parallel()

	_, mode, set, _, _, _, _, us, has, ok := parseStoreArg(`1 (UNCHANGEDSINCE 10) +FLAGS (\Seen)`)
	if !ok || !has || us != 10 || mode != storeAdd || set&mail.FlagSeen == 0 {
		t.Fatalf("parse %+v us=%d ok=%v", mode, us, ok)
	}
}
