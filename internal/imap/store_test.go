package imap

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
)

func TestParseStoreFlagsDeleted(t *testing.T) {
	t.Parallel()

	mode, set, clear, ok := parseStoreFlags(`+FLAGS (\Deleted)`)
	if !ok || mode != storeAdd || set != mail.FlagDeleted || clear != 0 {
		t.Fatalf("deleted add: mode=%d set=%#x clear=%#x ok=%v", mode, set, clear, ok)
	}

	mode, set, clear, ok = parseStoreFlags(`+FLAGS (\Seen \Deleted)`)
	if !ok || mode != storeAdd || set != (mail.FlagSeen|mail.FlagDeleted) {
		t.Fatalf("multi: mode=%d set=%#x ok=%v", mode, set, ok)
	}

	mode, set, clear, ok = parseStoreFlags(`+FLAGS (\Flagged)`)
	if !ok || mode != storeAdd || set != mail.FlagFlagged {
		t.Fatalf("flagged: mode=%d set=%#x ok=%v", mode, set, ok)
	}

	mode, set, clear, ok = parseStoreFlags(`+FLAGS.SILENT (\Deleted)`)
	if !ok || mode != storeAdd || set != mail.FlagDeleted {
		t.Fatalf("silent: mode=%d set=%#x ok=%v", mode, set, ok)
	}
}

func TestParseIMAPFlagList(t *testing.T) {
	t.Parallel()

	bits, ok := parseIMAPFlagList(`(\Seen \Deleted)`)
	if !ok || bits != (mail.FlagSeen|mail.FlagDeleted) {
		t.Fatalf("list %#x ok=%v", bits, ok)
	}
}
