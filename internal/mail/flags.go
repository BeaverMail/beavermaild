// IMAP-aligned message flags persisted in EmailMeta.Flags.
package mail

const (
	// FlagSeen is the \Seen flag (RFC 3501).
	FlagSeen uint32 = 1 << 0
)

// FormatIMAPFlags renders flags for IMAP FETCH/STORE responses.
func FormatIMAPFlags(f uint32) string {
	if f&FlagSeen != 0 {
		return `(\Seen)`
	}
	return "()"
}

// ParseIMAPFlagName maps an IMAP flag name to a bit (empty if unknown).
func ParseIMAPFlagName(name string) (uint32, bool) {
	switch name {
	case `\Seen`, "Seen":
		return FlagSeen, true
	default:
		return 0, false
	}
}

// IMAPCapabilityFlags is the FLAGS untagged line for SELECT.
const IMAPCapabilityFlags = `FLAGS (\Seen)`
