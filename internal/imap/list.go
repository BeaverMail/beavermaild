// IMAP LIST command: pattern matching and SPECIAL-USE attributes.
package imap

import (
	"regexp"
	"strings"

	"github.com/BeaverMail/beaver/internal/mail"
)

// listOptions captures LIST / LSUB reference, pattern, and LIST-EXTENDED flags.
type listOptions struct {
	ref            string
	pattern        string
	subscribedOnly bool
	markSubscribed bool
}

// parseListOptions parses LIST arguments including (SUBSCRIBED) and RETURN (SUBSCRIBED).
func parseListOptions(arg string) (listOptions, bool) {
	arg = strings.TrimSpace(arg)
	var opt listOptions

	for strings.HasPrefix(arg, "(") {
		end := strings.IndexByte(arg, ')')
		if end < 0 {
			return listOptions{}, false
		}
		if strings.Contains(strings.ToUpper(arg[1:end]), "SUBSCRIBED") {
			opt.subscribedOnly = true
			opt.markSubscribed = true
		}
		arg = strings.TrimSpace(arg[end+1:])
	}

	ref, rest, ok := parseListToken(arg)
	if !ok {
		return listOptions{}, false
	}
	pattern, rest, ok := parseListToken(rest)
	if !ok {
		return listOptions{}, false
	}
	opt.ref = ref
	opt.pattern = pattern

	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(strings.ToUpper(rest), "RETURN") {
		if i := strings.IndexByte(rest, '('); i >= 0 {
			if j := strings.IndexByte(rest[i:], ')'); j >= 0 {
				ret := strings.ToUpper(rest[i : i+j+1])
				if strings.Contains(ret, "SUBSCRIBED") {
					opt.markSubscribed = true
				}
			}
		}
		rest = ""
	}
	if rest != "" {
		return listOptions{}, false
	}
	return opt, true
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

// listMailboxAttrs returns IMAP LIST attributes for one folder (RFC 3501 + SPECIAL-USE).
func listMailboxAttrs(mb mail.Mailbox, allNames []string, markSubscribed bool) string {
	childAttr := `\HasNoChildren`
	if mailboxHasChildren(mb.Name, allNames) {
		childAttr = `\HasChildren`
	}
	attrs := childAttr
	if markSubscribed && mb.Subscribed {
		attrs += ` \Subscribed`
	}
	switch mb.ID {
	case mail.SentMailboxID:
		attrs += ` \Sent`
	case mail.TrashMailboxID:
		attrs += ` \Trash`
	case mail.DraftsMailboxID:
		attrs += ` \Drafts`
	}
	if isJunkMailbox(mb.Name) {
		attrs += ` \Junk`
	}
	return attrs
}

// isJunkMailbox reports well-known spam folder names for SPECIAL-USE \Junk.
func isJunkMailbox(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "SPAM", "JUNK", "BULK", "JUNK E-MAIL", "JUNK MAIL":
		return true
	default:
		return false
	}
}

// mailboxHasChildren reports whether any listed folder name is a direct or nested child.
func mailboxHasChildren(parent string, allNames []string) bool {
	parent = strings.TrimSpace(parent)
	if parent == "" {
		return false
	}
	prefix := strings.ToUpper(parent) + "/"
	for _, name := range allNames {
		upper := strings.ToUpper(strings.TrimSpace(name))
		if len(upper) > len(prefix) && strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}
