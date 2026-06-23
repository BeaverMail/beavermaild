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
}

func TestParseIMAPFlagName(t *testing.T) {
	t.Parallel()
	bit, ok := mail.ParseIMAPFlagName(`\Seen`)
	if !ok || bit != mail.FlagSeen {
		t.Fatalf("parse seen %v %d", ok, bit)
	}
	_, ok = mail.ParseIMAPFlagName(`\Deleted`)
	if ok {
		t.Fatal("unknown flag accepted")
	}
}
