package plugin

// IMAP system flag bits for batch messages (aligned with internal/mail).
const (
	FlagSeen     uint32 = 1 << 0
	FlagDraft    uint32 = 1 << 1
	FlagDeleted  uint32 = 1 << 2
	FlagAnswered uint32 = 1 << 3
	FlagFlagged  uint32 = 1 << 4
	FlagRecent   uint32 = 1 << 5
)
