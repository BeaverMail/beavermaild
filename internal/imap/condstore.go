// IMAP CONDSTORE: ENABLE and STORE UNCHANGEDSINCE parsing.
package imap

import (
	"strconv"
	"strings"
)

// cmdEnable activates optional IMAP extensions requested by the client (RFC 5162).
func (s *session) cmdEnable(tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return s.tagged(tag, "BAD ENABLE syntax")
	}
	var enabled []string
	for _, tok := range strings.Fields(strings.ToUpper(arg)) {
		switch tok {
		case "CONDSTORE":
			s.condstore = true
			enabled = append(enabled, "CONDSTORE")
		}
	}
	if len(enabled) == 0 {
		return s.tagged(tag, "BAD ENABLE syntax")
	}
	if err := s.untagged("ENABLED " + strings.Join(enabled, " ")); err != nil {
		return err
	}
	return s.tagged(tag, "OK ENABLE completed")
}

// parseUnchangedSince extracts a leading (UNCHANGEDSINCE n) or UNCHANGEDSINCE n clause.
func parseUnchangedSince(rest string) (since uint64, remaining string, ok bool) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return 0, rest, false
	}
	upper := strings.ToUpper(rest)
	const paren = "(UNCHANGEDSINCE "
	if strings.HasPrefix(upper, paren) {
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return 0, rest, false
		}
		num := strings.TrimSpace(rest[len(paren) : end])
		n, err := strconv.ParseUint(num, 10, 64)
		if err != nil {
			return 0, rest, false
		}
		return n, strings.TrimSpace(rest[end+1:]), true
	}
	if strings.HasPrefix(upper, "UNCHANGEDSINCE ") {
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			return 0, rest, false
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, rest, false
		}
		remaining = strings.TrimSpace(rest[len(fields[0])+len(fields[1])+1:])
		return n, remaining, true
	}
	return 0, rest, false
}

// parseTrailingUnchangedSince extracts a trailing (UNCHANGEDSINCE n) clause after STORE flags.
func parseTrailingUnchangedSince(rest string) (since uint64, remaining string, ok bool) {
	rest = strings.TrimSpace(rest)
	upper := strings.ToUpper(rest)
	const paren = "(UNCHANGEDSINCE "
	idx := strings.LastIndex(upper, paren)
	if idx < 0 {
		return 0, rest, false
	}
	tail := strings.TrimSpace(rest[idx:])
	if us, _, ok := parseUnchangedSince(tail); ok {
		return us, strings.TrimSpace(rest[:idx]), true
	}
	return 0, rest, false
}

func formatModSeq(modSeq uint64) string {
	return "MODSEQ (" + strconv.FormatUint(modSeq, 10) + ")"
}
