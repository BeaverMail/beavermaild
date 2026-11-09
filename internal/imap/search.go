// IMAP SEARCH argument parsing helpers (tokenize, dates, UID ranges).
package imap

import (
	"strconv"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// tokenizeSearchArg splits SEARCH arguments into atoms, unescaped quoted strings and literal
// contents (as assembled by readCommandLiterals: "{n}\r\n" followed by n bytes). It returns
// nil on malformed input. Only leading space is trimmed: a literal may end with whitespace.
func tokenizeSearchArg(arg string) []string {
	var tokens []string
	arg = strings.TrimLeft(arg, " \t")
	for len(arg) > 0 {
		switch arg[0] {
		case '(':
			tokens = append(tokens, "(")
			arg = strings.TrimLeft(arg[1:], " \t")
			continue
		case ')':
			tokens = append(tokens, ")")
			arg = strings.TrimLeft(arg[1:], " \t")
			continue
		case '"':
			val, rest, ok := cutQuotedString(arg)
			if !ok {
				return nil
			}
			tokens = append(tokens, val)
			arg = strings.TrimLeft(rest, " \t")
			continue
		case '{':
			val, rest, ok := cutLiteral(arg)
			if !ok {
				return nil
			}
			tokens = append(tokens, val)
			arg = strings.TrimLeft(rest, " \t")
			continue
		}
		i := strings.IndexAny(arg, " \t")
		word := arg
		if i >= 0 {
			word = arg[:i]
			arg = strings.TrimLeft(arg[i+1:], " \t")
		} else {
			arg = ""
		}
		tokens = appendSearchWordTokens(tokens, word)
	}
	return tokens
}

// cutQuotedString parses a leading IMAP quoted string, undoing \" and \\ escapes.
func cutQuotedString(s string) (val, rest string, ok bool) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) {
				return "", "", false
			}
			i++
			b.WriteByte(s[i])
		case '"':
			return b.String(), s[i+1:], true
		default:
			b.WriteByte(s[i])
		}
	}
	return "", "", false
}

// cutLiteral parses a leading "{n}\r\n" or "{n+}\r\n" marker and returns the n bytes after it.
func cutLiteral(s string) (val, rest string, ok bool) {
	end := strings.IndexByte(s, '}')
	if end < 0 {
		return "", "", false
	}
	n, err := strconv.Atoi(strings.TrimSuffix(s[1:end], "+"))
	if err != nil || n < 0 {
		return "", "", false
	}
	body := s[end+1:]
	if !strings.HasPrefix(body, "\r\n") || len(body)-2 < n {
		return "", "", false
	}
	return body[2 : 2+n], body[2+n:], true
}

// appendSearchWordTokens splits parentheses glued to SEARCH atoms (e.g. "ANSWERED)").
func appendSearchWordTokens(tokens []string, word string) []string {
	word = strings.TrimSpace(word)
	for len(word) > 0 {
		switch word[0] {
		case '(':
			tokens = append(tokens, "(")
			word = strings.TrimSpace(word[1:])
			continue
		case ')':
			tokens = append(tokens, ")")
			word = strings.TrimSpace(word[1:])
			continue
		}
		j := strings.IndexByte(word, ')')
		if j < 0 {
			tokens = append(tokens, word)
			break
		}
		if j > 0 {
			tokens = append(tokens, word[:j])
		}
		tokens = append(tokens, ")")
		word = strings.TrimSpace(word[j+1:])
	}
	return tokens
}

func parseIMAPDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("2-Jan-2006", s)
	if err != nil {
		return time.Time{}, false
	}
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), true
}

// parseSearchSeqSet parses an IMAP sequence set ("1", "2:4,7", "5:*", "*") into mail ranges.
func parseSearchSeqSet(tok string) ([]mail.SeqRange, bool) {
	if tok == "" || (tok[0] != '*' && (tok[0] < '0' || tok[0] > '9')) {
		return nil, false
	}
	set, err := parseSeqSet(tok)
	if err != nil {
		return nil, false
	}
	out := make([]mail.SeqRange, len(set.ranges))
	for i, r := range set.ranges {
		out[i] = mail.SeqRange{Lo: r.lo, Hi: r.hi}
	}
	return out, true
}
