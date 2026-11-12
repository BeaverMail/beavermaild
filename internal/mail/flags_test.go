package mail_test

import (
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

func TestFormatIMAPFlags(t *testing.T) {
	t.Parallel()
	if got := mail.FormatIMAPFlags(0); got != "()" {
		t.Fatalf("empty %q", got)
	}
	if got := mail.FormatIMAPFlags(mail.FlagSeen); got != `(\Seen)` {
		t.Fatalf("seen %q", got)
	}
	if got := mail.FormatIMAPFlags(mail.FlagFlagged | mail.FlagSeen); got != `(\Flagged \Seen)` {
		t.Fatalf("flagged seen %q", got)
	}
}

func TestParseIMAPFlagName(t *testing.T) {
	t.Parallel()
	bit, ok := mail.ParseIMAPFlagName(`\Seen`)
	if !ok || bit != mail.FlagSeen {
		t.Fatalf("parse seen %v %d", ok, bit)
	}
	bit, ok = mail.ParseIMAPFlagName(`\Deleted`)
	if !ok || bit != mail.FlagDeleted {
		t.Fatalf("parse deleted %v %d", ok, bit)
	}
	bit, ok = mail.ParseIMAPFlagName(`\Answered`)
	if !ok || bit != mail.FlagAnswered {
		t.Fatalf("parse answered %v %d", ok, bit)
	}
	bit, ok = mail.ParseIMAPFlagName(`\Flagged`)
	if !ok || bit != mail.FlagFlagged {
		t.Fatalf("parse flagged %v %d", ok, bit)
	}
	bit, ok = mail.ParseIMAPFlagName(`\Recent`)
	if !ok || bit != mail.FlagRecent {
		t.Fatalf("parse recent %v %d", ok, bit)
	}
}

func TestIsStoreableFlag(t *testing.T) {
	t.Parallel()
	if !mail.IsStoreableFlag(mail.FlagFlagged) {
		t.Fatal("flagged storeable")
	}
	if mail.IsStoreableFlag(mail.FlagRecent) {
		t.Fatal("recent not storeable")
	}
}

func TestParseIMAPFlagNameCaseInsensitive(t *testing.T) {
	t.Parallel()
	for _, name := range []string{`\Seen`, `\seen`, `\SEEN`} {
		if b, ok := mail.ParseIMAPFlagName(name); !ok || b != mail.FlagSeen {
			t.Fatalf("%q -> %d %v", name, b, ok)
		}
	}
	// Without the backslash it is an ordinary keyword (RFC 3501 2.3.2), whatever its case.
	for _, name := range []string{"Seen", "seen"} {
		if _, ok := mail.ParseIMAPFlagName(name); ok {
			t.Fatalf(`bare %q taken as \Seen`, name)
		}
	}
	if _, ok := mail.ParseIMAPFlagName(`\Junk`); ok {
		t.Fatal(`\Junk taken as a system flag`)
	}
}

// Keywords are IMAP atoms (RFC 3501 9 flag-keyword): anything else would be echoed into the FLAGS
// and PERMANENTFLAGS of every session and break their parsing (CVE-2019-11500 class: NUL).
func TestValidKeyword(t *testing.T) {
	t.Parallel()
	for _, kw := range []string{"$Label1", "Seen", "$Forwarded", "NonJunk", "a.b-c_d:e"} {
		if !mail.ValidKeyword(kw) {
			t.Errorf("%q refused", kw)
		}
	}
	for _, kw := range []string{"", "k\x00w", "k]w", `k"w`, "k{3}w", "k%w", "k*w", "k(w", "k)w", `k\w`, "k w", "k\x7fw", "caf\xc3\xa9", strings.Repeat("a", 129)} {
		if mail.ValidKeyword(kw) {
			t.Errorf("%q accepted", kw)
		}
	}
}
