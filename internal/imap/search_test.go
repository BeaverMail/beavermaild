package imap

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
)

func TestParseIMAPFlagListIgnoresRecent(t *testing.T) {
	t.Parallel()

	bits, ok := parseIMAPFlagList(`(\Recent \Seen)`)
	if !ok || bits != mail.FlagSeen {
		t.Fatalf("store list %#x ok=%v", bits, ok)
	}
}

func TestParseSearchFlagged(t *testing.T) {
	t.Parallel()

	c, ok := parseSearchExpr("FLAGGED")
	if !ok || c.Kind != mail.SearchExprCrit || c.Crit.Flagged == nil || !*c.Crit.Flagged {
		t.Fatalf("flagged %+v ok=%v", c, ok)
	}

	c, ok = parseSearchExpr("NEW")
	if !ok || c.Crit.Recent == nil || !*c.Crit.Recent || c.Crit.Seen == nil || *c.Crit.Seen {
		t.Fatalf("new %+v ok=%v", c, ok)
	}
}
