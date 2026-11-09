// IMAP-aligned message flags persisted in EmailMeta.Flags.
package mail

import "strings"

const (
	// FlagSeen is the \Seen flag (RFC 3501).
	FlagSeen uint32 = 1 << 0
	// FlagDraft is the \Draft flag (RFC 3501).
	FlagDraft uint32 = 1 << 1
	// FlagDeleted is the \Deleted flag (RFC 3501); removed by IMAP EXPUNGE.
	FlagDeleted uint32 = 1 << 2
	// FlagAnswered is the \Answered flag (RFC 3501).
	FlagAnswered uint32 = 1 << 3
	// FlagFlagged is the \Flagged flag (RFC 3501).
	FlagFlagged uint32 = 1 << 4
	// FlagRecent is the \Recent flag (RFC 3501); cleared when the mailbox is selected.
	FlagRecent uint32 = 1 << 5
)

// StoreableIMAPFlags are system flags clients may change via IMAP STORE.
const StoreableIMAPFlags = FlagSeen | FlagDraft | FlagDeleted | FlagAnswered | FlagFlagged

// IMAPCapabilityFlags is the FLAGS untagged line for SELECT (RFC 3501 order).
const IMAPCapabilityFlags = `FLAGS (\Answered \Flagged \Deleted \Seen \Draft)`

// IMAPPermanentFlags is the PERMANENTFLAGS response code payload (excludes \Recent).
const IMAPPermanentFlags = `(\Answered \Flagged \Deleted \Seen \Draft \*)`

// FormatIMAPFlags renders flags for IMAP FETCH/STORE responses.
func FormatIMAPFlags(f uint32) string {
	var names []string
	if f&FlagAnswered != 0 {
		names = append(names, `\Answered`)
	}
	if f&FlagFlagged != 0 {
		names = append(names, `\Flagged`)
	}
	if f&FlagDeleted != 0 {
		names = append(names, `\Deleted`)
	}
	if f&FlagSeen != 0 {
		names = append(names, `\Seen`)
	}
	if f&FlagDraft != 0 {
		names = append(names, `\Draft`)
	}
	if f&FlagRecent != 0 {
		names = append(names, `\Recent`)
	}
	if len(names) == 0 {
		return "()"
	}
	return "(" + strings.Join(names, " ") + ")"
}

// ParseIMAPFlagName maps an IMAP system flag name to a bit (empty if unknown).
func ParseIMAPFlagName(name string) (uint32, bool) {
	// System flags are case-insensitive (RFC 3501: \seen is \Seen); bare names stay exact.
	if rest, ok := strings.CutPrefix(name, `\`); ok {
		name = rest
		for _, f := range systemFlagNames {
			if strings.EqualFold(name, f.name) {
				return f.bit, true
			}
		}
		return 0, false
	}
	for _, f := range systemFlagNames {
		if name == f.name {
			return f.bit, true
		}
	}
	return 0, false
}

var systemFlagNames = []struct {
	name string
	bit  uint32
}{
	{"Seen", FlagSeen}, {"Draft", FlagDraft}, {"Deleted", FlagDeleted},
	{"Answered", FlagAnswered}, {"Flagged", FlagFlagged}, {"Recent", FlagRecent},
}

// IsStoreableFlag reports whether clients may set or clear the flag via STORE.
func IsStoreableFlag(f uint32) bool {
	return f != 0 && f&StoreableIMAPFlags == f
}
