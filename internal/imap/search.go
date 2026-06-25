// IMAP SEARCH argument parsing helpers (tokenize, dates, UID ranges).
package imap

import (
	"strconv"
	"strings"
	"time"
)

func tokenizeSearchArg(arg string) []string {
	var tokens []string
	arg = strings.TrimSpace(arg)
	for len(arg) > 0 {
		switch arg[0] {
		case '(':
			tokens = append(tokens, "(")
			arg = strings.TrimSpace(arg[1:])
			continue
		case ')':
			tokens = append(tokens, ")")
			arg = strings.TrimSpace(arg[1:])
			continue
		}
		if arg[0] == '"' {
			val, rest, ok := parseQuoted(arg)
			if !ok {
				return nil
			}
			tokens = append(tokens, val)
			arg = strings.TrimSpace(rest)
			continue
		}
		i := strings.IndexByte(arg, ' ')
		word := arg
		if i >= 0 {
			word = arg[:i]
			arg = strings.TrimSpace(arg[i+1:])
		} else {
			arg = ""
		}
		tokens = appendSearchWordTokens(tokens, word)
	}
	return tokens
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

func parseUIDSearchRange(tok string) (lo, hi uint32, ok bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return 0, 0, false
	}
	if strings.Contains(tok, ":") {
		i := strings.IndexByte(tok, ':')
		lo, err := strconv.ParseUint(strings.TrimSpace(tok[:i]), 10, 32)
		if err != nil || lo == 0 {
			return 0, 0, false
		}
		hiPart := strings.TrimSpace(tok[i+1:])
		if hiPart == "*" {
			return uint32(lo), ^uint32(0), true
		}
		hi, err := strconv.ParseUint(hiPart, 10, 32)
		if err != nil || hi == 0 || uint32(hi) < uint32(lo) {
			return 0, 0, false
		}
		return uint32(lo), uint32(hi), true
	}
	n, err := strconv.ParseUint(tok, 10, 32)
	if err != nil || n == 0 {
		return 0, 0, false
	}
	return uint32(n), uint32(n), true
}
