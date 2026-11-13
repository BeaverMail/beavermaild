// SMTP address validation for ASCII and SMTPUTF8 paths.
package smtp

import (
	"strings"
	"unicode/utf8"
)

// addressNeedsUTF8 reports whether addr contains non-ASCII Unicode.
func addressNeedsUTF8(addr string) bool {
	for _, r := range addr {
		if r > 127 {
			return true
		}
	}
	return false
}

// validEnvelopeAddress checks minimal envelope syntax for ASCII or UTF-8 addresses; the local part may be
// a Quoted-string (RFC 5321 4.1.2), the only form in which it may hold spaces.
func validEnvelopeAddress(addr string) bool {
	if !utf8.ValidString(addr) {
		return false
	}
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return false
	}
	local := addr[:at]
	domain := addr[at+1:]
	if strings.ContainsAny(domain, " \t\r\n") {
		return false
	}
	if len(local) >= 2 && local[0] == '"' && local[len(local)-1] == '"' {
		return validQuotedContent(local[1 : len(local)-1])
	}
	return !strings.ContainsAny(local, " \t\r\n")
}

// validQuotedContent checks *QcontentSMTP: qtextSMTP (%d32-33 / %d35-91 / %d93-126, UTF-8 with SMTPUTF8)
// or a quoted-pair backslash %d32-126.
func validQuotedContent(q string) bool {
	for i := 0; i < len(q); i++ {
		switch c := q[i]; {
		case c == '\\':
			if i++; i == len(q) || q[i] < 32 || q[i] > 126 {
				return false
			}
		case c == '"' || c < 32 || c == 127:
			return false
		}
	}
	return true
}

// parsePath extracts the mailbox from "<path> params" (RFC 5321 4.1.2): a ">" inside a quoted local part
// does not end it, a source route (A-d-l) is dropped (3.6.1: "SHOULD ignore the routes"), and a quoted
// local part that is a plain Dot-string loses its quotes, so "alice"@x is alice@x. rest is the text
// after ">". Text before "<" is tolerated for broken clients ("MAIL FROM: Name <a@b>").
func parsePath(arg string) (mailbox, rest string, ok bool) {
	lt := strings.IndexByte(arg, '<')
	if lt < 0 {
		return "", "", false
	}
	inQuote := false
	for i := lt + 1; i < len(arg); i++ {
		switch c := arg[i]; {
		case inQuote && c == '\\':
			i++
		case c == '"':
			inQuote = !inQuote
		case c == '>' && !inQuote:
			path, ok := dropSourceRoute(strings.TrimSpace(arg[lt+1 : i]))
			return unquoteLocal(path), arg[i+1:], ok
		}
	}
	return "", "", false
}

// dropSourceRoute strips A-d-l = At-domain *( "," At-domain ) ":" from the front of a path.
func dropSourceRoute(path string) (string, bool) {
	if !strings.HasPrefix(path, "@") {
		return path, true
	}
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '[': // address literal: may hold ':' (IPv6)
			end := strings.IndexByte(path[i:], ']')
			if end < 0 {
				return "", false
			}
			i += end
		case ':':
			return path[i+1:], true
		}
	}
	return "", false
}

// unquoteLocal turns "local"@domain into local@domain when the quotes add nothing (a valid Dot-string).
func unquoteLocal(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at < 2 || addr[0] != '"' || addr[at-1] != '"' {
		return addr
	}
	inner := addr[1 : at-1]
	if !isDotString(inner) {
		return addr
	}
	return inner + addr[at:]
}

// isDotString reports Atom *("." Atom) with RFC 5322 atext (and UTF-8, RFC 6531).
func isDotString(s string) bool {
	if s == "" || s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 128 || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-/=?^_`{|}~.", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// normalizeEnvelopeAddress lowercases the domain only: RFC 5321 2.4 makes the local part case-sensitive
// for everyone but its own domain (the directory folds case for our users).
func normalizeEnvelopeAddress(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return addr
	}
	return addr[:at+1] + strings.ToLower(addr[at+1:])
}

// validDomain checks an RFC 5321 4.1.2 Domain in A-label form (DomainFromAddress output): dot-separated
// sub-domains of letters, digits and inner hyphens (Let-dig [Ldh-str]), labels of at most 63 octets,
// the whole at most 255 (4.5.3.1.2). A U-label that IDNA rejects stays non-ASCII and fails here.
func validDomain(d string) bool {
	if d == "" || len(d) > 255 {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
