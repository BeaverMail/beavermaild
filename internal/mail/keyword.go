// IMAP keyword flags (custom FLAGS beyond system bits).
package mail

import (
	"strings"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// NormalizeKeyword canonicalizes an IMAP keyword for storage and comparison.
func NormalizeKeyword(name string) string {
	return strings.TrimSpace(name)
}

// ValidKeyword reports whether name is a flag-keyword: an IMAP atom (RFC 3501 9), so any CHAR
// except CTL, SP, NUL, 8-bit and the atom-specials ( ) { % * " \ ]. Anything else stored as a
// keyword would be echoed into FLAGS and PERMANENTFLAGS of every session and break their parsing.
func ValidKeyword(name string) bool {
	if name == "" || len(name) > maxKeywordLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`(){%*"\]`, c) >= 0 {
			return false
		}
	}
	return true
}

// maxKeywordLen bounds one keyword; FLAGS lists every keyword in use in the mailbox.
const maxKeywordLen = 128

// HasKeyword reports whether meta carries the IMAP keyword (system or custom).
func HasKeyword(meta storage.EmailMeta, keyword string) bool {
	keyword = NormalizeKeyword(keyword)
	if keyword == "" {
		return false
	}
	if bit, ok := ParseIMAPFlagName(keyword); ok {
		return meta.Flags&bit != 0
	}
	for _, kw := range meta.Keywords {
		if strings.EqualFold(kw, keyword) {
			return true
		}
	}
	return false
}

// AllKeywords in ApplyKeywords' remove list drops every custom keyword (STORE FLAGS replace).
const AllKeywords = `\*`

// ApplyKeywords adds and removes custom keywords on meta (system flags use Flags bits).
func ApplyKeywords(meta *storage.EmailMeta, add, remove []string) {
	for _, name := range remove {
		if name == AllKeywords {
			meta.Keywords = nil
			continue
		}
		name = NormalizeKeyword(name)
		if bit, ok := ParseIMAPFlagName(name); ok {
			meta.Flags &^= bit
			continue
		}
		meta.Keywords = removeKeyword(meta.Keywords, name)
	}
	for _, name := range add {
		name = NormalizeKeyword(name)
		if bit, ok := ParseIMAPFlagName(name); ok {
			if IsStoreableFlag(bit) {
				meta.Flags |= bit
			}
			continue
		}
		if name == "" || HasKeyword(*meta, name) {
			continue
		}
		meta.Keywords = append(meta.Keywords, name)
	}
}

func removeKeyword(kws []string, name string) []string {
	out := kws[:0]
	for _, kw := range kws {
		if !strings.EqualFold(kw, name) {
			out = append(out, kw)
		}
	}
	return out
}

// FormatMessageFlags renders system flags and custom keywords for IMAP FETCH/STORE.
func FormatMessageFlags(meta storage.EmailMeta) string {
	var names []string
	if meta.Flags&FlagAnswered != 0 {
		names = append(names, `\Answered`)
	}
	if meta.Flags&FlagFlagged != 0 {
		names = append(names, `\Flagged`)
	}
	if meta.Flags&FlagDeleted != 0 {
		names = append(names, `\Deleted`)
	}
	if meta.Flags&FlagSeen != 0 {
		names = append(names, `\Seen`)
	}
	if meta.Flags&FlagDraft != 0 {
		names = append(names, `\Draft`)
	}
	if meta.Flags&FlagRecent != 0 {
		names = append(names, `\Recent`)
	}
	for _, kw := range meta.Keywords {
		if ValidKeyword(kw) { // stored before keywords were validated: never echo a broken atom
			names = append(names, kw)
		}
	}
	if len(names) == 0 {
		return "()"
	}
	return "(" + strings.Join(names, " ") + ")"
}
