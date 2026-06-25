package imap

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
)

func TestParseStoreFlagsDeleted(t *testing.T) {
	t.Parallel()

	mode, set, clear, kwAdd, kwRemove, ok := parseStoreFlags(`+FLAGS (\Deleted)`)
	if !ok || mode != storeAdd || set != mail.FlagDeleted || clear != 0 || len(kwAdd) != 0 || len(kwRemove) != 0 {
		t.Fatalf("deleted add: mode=%d set=%#x clear=%#x kwAdd=%v kwRemove=%v ok=%v", mode, set, clear, kwAdd, kwRemove, ok)
	}

	mode, set, clear, kwAdd, kwRemove, ok = parseStoreFlags(`+FLAGS (\Seen \Deleted)`)
	if !ok || mode != storeAdd || set != (mail.FlagSeen|mail.FlagDeleted) {
		t.Fatalf("multi: mode=%d set=%#x ok=%v", mode, set, ok)
	}

	mode, set, clear, kwAdd, kwRemove, ok = parseStoreFlags(`+FLAGS (\Flagged)`)
	if !ok || mode != storeAdd || set != mail.FlagFlagged {
		t.Fatalf("flagged: mode=%d set=%#x ok=%v", mode, set, ok)
	}

	mode, set, clear, kwAdd, kwRemove, ok = parseStoreFlags(`+FLAGS.SILENT (\Deleted)`)
	if !ok || mode != storeAdd || set != mail.FlagDeleted {
		t.Fatalf("silent: mode=%d set=%#x ok=%v", mode, set, ok)
	}

	mode, set, clear, kwAdd, kwRemove, ok = parseStoreFlags(`+FLAGS (Flag_007)`)
	if !ok || mode != storeAdd || len(kwAdd) != 1 || kwAdd[0] == "" {
		t.Fatalf("keyword add: kwAdd=%v ok=%v", kwAdd, ok)
	}
}

func TestParseIMAPFlagList(t *testing.T) {
	t.Parallel()

	bits, kws, ok := parseIMAPFlagList(`(\Seen \Deleted)`)
	if !ok || bits != (mail.FlagSeen|mail.FlagDeleted) || len(kws) != 0 {
		t.Fatalf("list %#x kws=%v ok=%v", bits, kws, ok)
	}
}
