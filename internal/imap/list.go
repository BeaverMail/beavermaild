// IMAP LIST command: pattern matching and SPECIAL-USE attributes.
package imap

import (
	"regexp"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// listOptions captures LIST / LSUB reference, patterns, and LIST-EXTENDED options (RFC 5258, RFC 6154).
type listOptions struct {
	ref            string
	patterns       []string
	extended       bool // RFC 5258 syntax: selection options, pattern list, or return options
	subscribedOnly bool
	specialUseOnly bool
	recursiveMatch bool
	markSubscribed bool
}

// parseListOptions parses `[(select-opts)] ref (pattern | (patterns)) [RETURN (return-opts)]`.
func parseListOptions(arg string) (listOptions, bool) {
	arg = strings.TrimSpace(arg)
	var opt listOptions

	if strings.HasPrefix(arg, "(") {
		sel, rest, ok := parseListAtoms(arg)
		if !ok {
			return listOptions{}, false
		}
		opt.extended = true
		for _, o := range sel {
			switch o {
			case "SUBSCRIBED":
				opt.subscribedOnly = true
				opt.markSubscribed = true
			case "SPECIAL-USE":
				opt.specialUseOnly = true
			case "RECURSIVEMATCH":
				opt.recursiveMatch = true
			case "REMOTE": // no remote mailboxes: nothing to add
			default:
				return listOptions{}, false
			}
		}
		// RFC 5258 §3: RECURSIVEMATCH needs another selection option besides REMOTE.
		if opt.recursiveMatch && !opt.subscribedOnly && !opt.specialUseOnly {
			return listOptions{}, false
		}
		arg = rest
	}

	ref, rest, ok := parseListToken(arg)
	if !ok {
		return listOptions{}, false
	}
	opt.ref = ref
	if strings.HasPrefix(rest, "(") {
		opt.patterns, rest, ok = parseListPatterns(rest)
		opt.extended = true
	} else {
		var pattern string
		pattern, rest, ok = parseListToken(rest)
		opt.patterns = []string{pattern}
	}
	if !ok {
		return listOptions{}, false
	}

	rest = strings.TrimSpace(rest)
	if len(rest) >= 6 && strings.EqualFold(rest[:6], "RETURN") {
		ret, after, ok := parseListAtoms(strings.TrimSpace(rest[6:]))
		if !ok {
			return listOptions{}, false
		}
		opt.extended = true
		for _, o := range ret {
			switch o {
			case "SUBSCRIBED":
				opt.markSubscribed = true
			case "CHILDREN", "SPECIAL-USE": // always returned
			default:
				return listOptions{}, false
			}
		}
		rest = after
	}
	if rest != "" {
		return listOptions{}, false
	}
	return opt, true
}

// parseListAtoms parses a parenthesized list of option atoms, upper-cased.
func parseListAtoms(arg string) (atoms []string, rest string, ok bool) {
	if !strings.HasPrefix(arg, "(") {
		return nil, "", false
	}
	end := strings.IndexByte(arg, ')')
	if end < 0 {
		return nil, "", false
	}
	return strings.Fields(strings.ToUpper(arg[1:end])), strings.TrimSpace(arg[end+1:]), true
}

// parseListPatterns parses a parenthesized list of quoted or atom mailbox patterns.
func parseListPatterns(arg string) (pats []string, rest string, ok bool) {
	arg = strings.TrimSpace(arg[1:])
	for {
		if strings.HasPrefix(arg, ")") {
			return pats, strings.TrimSpace(arg[1:]), len(pats) > 0
		}
		var tok string
		if strings.HasPrefix(arg, `"`) {
			if tok, arg, ok = parseQuoted(arg); !ok {
				return nil, "", false
			}
		} else {
			i := strings.IndexAny(arg, " )")
			if i <= 0 {
				return nil, "", false
			}
			tok, arg = arg[:i], strings.TrimSpace(arg[i:])
		}
		pats = append(pats, tok)
	}
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
	if su := specialUseAttr(mb); su != "" {
		attrs += " " + su
	}
	return attrs
}

// specialUseAttr returns the RFC 6154 attribute for a folder, or "".
func specialUseAttr(mb mail.Mailbox) string {
	switch mb.ID {
	case mail.SentMailboxID:
		return `\Sent`
	case mail.TrashMailboxID:
		return `\Trash`
	case mail.DraftsMailboxID:
		return `\Drafts`
	}
	if isJunkMailbox(mb.Name) {
		return `\Junk`
	}
	return ""
}

// listCandidate is a folder LIST can return; virtual ones are missing parents of existing folders.
type listCandidate struct {
	mb      mail.Mailbox
	virtual bool
}

// listCandidates returns existing folders plus their missing ancestors, each parent before its children.
func listCandidates(mboxes []mail.Mailbox) []listCandidate {
	seen := make(map[string]bool, len(mboxes))
	for _, mb := range mboxes {
		seen[strings.ToUpper(mb.Name)] = true
	}
	out := make([]listCandidate, 0, len(mboxes))
	for _, mb := range mboxes {
		for i := strings.IndexByte(mb.Name, '/'); i >= 0; i = nextSlash(mb.Name, i) {
			parent := mb.Name[:i]
			if parent != "" && !seen[strings.ToUpper(parent)] {
				seen[strings.ToUpper(parent)] = true
				out = append(out, listCandidate{mb: mail.Mailbox{Name: parent}, virtual: true})
			}
		}
		out = append(out, listCandidate{mb: mb})
	}
	return out
}

func nextSlash(name string, i int) int {
	j := strings.IndexByte(name[i+1:], '/')
	if j < 0 {
		return -1
	}
	return i + 1 + j
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
