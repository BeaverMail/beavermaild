package mail_test

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
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
