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

	c, ok := parseSearchCriteria("FLAGGED")
	if !ok || c.Flagged == nil || !*c.Flagged {
		t.Fatalf("flagged %+v ok=%v", c, ok)
	}

	c, ok = parseSearchCriteria("NEW")
	if !ok || c.Recent == nil || !*c.Recent || c.Seen == nil || *c.Seen {
		t.Fatalf("new %+v ok=%v", c, ok)
	}
}
