// IMAP keyword flags (custom FLAGS beyond system bits).
package mail

import (
	"strings"

	"github.com/BeaverMail/beaver/internal/storage"
)

// NormalizeKeyword canonicalizes an IMAP keyword for storage and comparison.
func NormalizeKeyword(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if !strings.HasPrefix(name, `\`) {
		if _, ok := ParseIMAPFlagName(`\` + name); ok {
			return `\` + name
		}
		return name
	}
	return name
}

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

// ApplyKeywords adds and removes custom keywords on meta (system flags use Flags bits).
func ApplyKeywords(meta *storage.EmailMeta, add, remove []string) {
	for _, name := range remove {
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
	names = append(names, meta.Keywords...)
	if len(names) == 0 {
		return "()"
	}
	return "(" + strings.Join(names, " ") + ")"
}
