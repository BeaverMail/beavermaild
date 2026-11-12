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
		if strings.HasPrefix(arg, `"`) || strings.HasPrefix(arg, "{") {
			if tok, arg, ok = cutAString(arg); !ok {
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
	return cutAString(arg)
}

// compileListPattern builds a matcher for IMAP LIST wildcards (* and %).
// Pattern and names are compared as mail.MailboxKey, the server's case rule for names.
func compileListPattern(pattern string) func(string) bool {
	pattern = mail.MailboxKey(pattern)
	if !strings.ContainsAny(pattern, "*%") {
		return func(name string) bool { return mail.MailboxKey(name) == pattern }
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			b.WriteString(".*")
		case '%':
			b.WriteString("[^/]*")
		default: // only * and % are wildcards: everything else matches itself (RFC 3501 6.3.8)
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	b.WriteString("$")
	re := regexp.MustCompile(b.String())
	return func(name string) bool { return re.MatchString(mail.MailboxKey(name)) }
}

// listMailboxAttrs returns IMAP LIST attributes for one folder (RFC 3501 + SPECIAL-USE).
func listMailboxAttrs(mb mail.Mailbox, parents parentSet, markSubscribed bool) string {
	childAttr := `\HasNoChildren`
	if parents.has(mb.Name) {
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
	mb          mail.Mailbox
	virtual     bool
	nonexistent bool // a subscription left by a deleted folder
}

// listCandidates returns existing folders plus their missing ancestors, each parent before its children.
func listCandidates(mboxes []mail.Mailbox) []listCandidate {
	seen := make(map[string]bool, len(mboxes))
	for _, mb := range mboxes {
		seen[mail.MailboxKey(mb.Name)] = true
	}
	out := make([]listCandidate, 0, len(mboxes))
	for _, mb := range mboxes {
		for i := strings.IndexByte(mb.Name, '/'); i >= 0; i = nextSlash(mb.Name, i) {
			parent := mb.Name[:i]
			if parent != "" && !seen[mail.MailboxKey(parent)] {
				seen[mail.MailboxKey(parent)] = true
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

// parentSet holds, upper-cased, every name that some folder lies under. Built once per LIST in
// O(folders x depth): asking every folder about every other one made LIST quadratic (2000
// nested folders took 12 s per LIST, 25 s per LSUB).
type parentSet map[string]bool

func newParentSet(names []string) parentSet {
	p := parentSet{}
	for _, n := range names {
		p.addAncestors(n)
	}
	return p
}

// addAncestors records every proper superior of name ("a" and "a/b" for "a/b/c").
func (p parentSet) addAncestors(name string) {
	key := mail.MailboxKey(name)
	for i := strings.IndexByte(key, '/'); i >= 0; i = nextSlash(key, i) {
		if i > 0 {
			p[key[:i]] = true
		}
	}
}

// has reports whether some folder lies under name.
func (p parentSet) has(name string) bool { return p[mail.MailboxKey(name)] }
