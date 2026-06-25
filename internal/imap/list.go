// IMAP LIST command: pattern matching and SPECIAL-USE attributes.
package imap

import (
	"regexp"
	"strings"

	"github.com/BeaverMail/beaver/internal/mail"
)

func parseListArg(arg string) (ref, pattern string, ok bool) {
	ref, rest, ok := parseListToken(arg)
	if !ok {
		return "", "", false
	}
	pattern, rest, ok = parseListToken(rest)
	if !ok || strings.TrimSpace(rest) != "" {
		return "", "", false
	}
	return ref, pattern, true
}

func parseListToken(arg string) (tok, rest string, ok bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", "", false
	}
	if arg[0] == '"' {
		tok, rest, ok = parseQuoted(arg)
		return tok, rest, ok
	}
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		return arg, "", true
	}
	return arg[:i], strings.TrimSpace(arg[i+1:]), true
}

// compileListPattern builds a matcher for IMAP LIST wildcards (* and %).
func compileListPattern(pattern string) func(string) bool {
	pattern = strings.TrimSpace(pattern)
	if len(pattern) >= 2 && pattern[0] == '"' && pattern[len(pattern)-1] == '"' {
		pattern = pattern[1 : len(pattern)-1]
	}
	if !strings.ContainsAny(pattern, "*%") {
		return func(name string) bool {
			return strings.EqualFold(pattern, name)
		}
	}
	var b strings.Builder
	b.WriteString("(?i)^")
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			b.WriteString(".*")
		case '%':
			b.WriteString("[^/]*")
		case '.', '+', '(', ')', '[', ']', '{', '}', '|', '^', '$', '\\':
			b.WriteString(`\`)
			b.WriteByte(pattern[i])
		default:
			b.WriteByte(pattern[i])
		}
	}
	b.WriteString("$")
	re := regexp.MustCompile(b.String())
	return func(name string) bool {
		if re.MatchString(name) {
			return true
		}
		return strings.EqualFold(name, "INBOX") && re.MatchString("INBOX")
	}
}

func listMailboxAttrs(mailboxID uint32) string {
	switch mailboxID {
	case mail.SentMailboxID:
		return `\HasNoChildren \Sent`
	case mail.TrashMailboxID:
		return `\HasNoChildren \Trash`
	case mail.DraftsMailboxID:
		return `\HasNoChildren \Drafts`
	default:
		return `\HasNoChildren`
	}
}
