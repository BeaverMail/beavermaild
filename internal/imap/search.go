// IMAP SEARCH argument parsing.
package imap

import (
	"strconv"
	"strings"
	"time"

	"github.com/BeaverMail/beaver/internal/mail"
)

// parseSearchCriteria parses SEARCH filters (flags, UID, header, date).
func parseSearchCriteria(arg string) (mail.SearchCriteria, bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return mail.SearchCriteria{}, false
	}
	tokens := tokenizeSearchArg(arg)
	if len(tokens) == 0 {
		return mail.SearchCriteria{}, false
	}
	var c mail.SearchCriteria
	for i := 0; i < len(tokens); i++ {
		key := strings.ToUpper(tokens[i])
		switch key {
		case "ALL":
			c.All = true
		case "NEW":
			v := true
			c.Recent = &v
			seen := false
			c.Seen = &seen
		case "OLD":
			v := false
			c.Recent = &v
		case "RECENT":
			v := true
			c.Recent = &v
		case "SEEN":
			v := true
			c.Seen = &v
		case "UNSEEN":
			v := false
			c.Seen = &v
		case "FLAGGED":
			v := true
			c.Flagged = &v
		case "UNFLAGGED":
			v := false
			c.Flagged = &v
		case "ANSWERED":
			v := true
			c.Answered = &v
		case "UNANSWERED":
			v := false
			c.Answered = &v
		case "DELETED":
			v := true
			c.Deleted = &v
		case "UNDELETED":
			v := false
			c.Deleted = &v
		case "DRAFT":
			v := true
			c.Draft = &v
		case "UNDRAFT":
			v := false
			c.Draft = &v
		case "UID":
			if i+1 >= len(tokens) {
				return mail.SearchCriteria{}, false
			}
			lo, hi, ok := parseUIDSearchRange(tokens[i+1])
			if !ok {
				return mail.SearchCriteria{}, false
			}
			c.UIDSet = true
			c.UIDMin = lo
			c.UIDMax = hi
			i++
		case "FROM":
			if i+1 >= len(tokens) {
				return mail.SearchCriteria{}, false
			}
			c.From = tokens[i+1]
			i++
		case "TO":
			if i+1 >= len(tokens) {
				return mail.SearchCriteria{}, false
			}
			c.To = tokens[i+1]
			i++
		case "SUBJECT":
			if i+1 >= len(tokens) {
				return mail.SearchCriteria{}, false
			}
			c.Subject = tokens[i+1]
			i++
		case "HEADER":
			if i+2 >= len(tokens) {
				return mail.SearchCriteria{}, false
			}
			c.Headers = append(c.Headers, mail.HeaderCriterion{
				Field: tokens[i+1],
				Value: tokens[i+2],
			})
			i += 2
		case "SINCE":
			if i+1 >= len(tokens) {
				return mail.SearchCriteria{}, false
			}
			t, ok := parseIMAPDate(tokens[i+1])
			if !ok {
				return mail.SearchCriteria{}, false
			}
			c.Since = &t
			i++
		case "BEFORE":
			if i+1 >= len(tokens) {
				return mail.SearchCriteria{}, false
			}
			t, ok := parseIMAPDate(tokens[i+1])
			if !ok {
				return mail.SearchCriteria{}, false
			}
			c.Before = &t
			i++
		case "ON":
			if i+1 >= len(tokens) {
				return mail.SearchCriteria{}, false
			}
			t, ok := parseIMAPDate(tokens[i+1])
			if !ok {
				return mail.SearchCriteria{}, false
			}
			c.On = &t
			i++
		default:
			return mail.SearchCriteria{}, false
		}
	}
	if !c.All && c.Seen == nil && !c.UIDSet && c.Flagged == nil && c.Answered == nil &&
		c.Deleted == nil && c.Draft == nil && c.Recent == nil &&
		c.From == "" && c.To == "" && c.Subject == "" && len(c.Headers) == 0 &&
		c.Since == nil && c.Before == nil && c.On == nil {
		return mail.SearchCriteria{}, false
	}
	return c, true
}

func tokenizeSearchArg(arg string) []string {
	var tokens []string
	arg = strings.TrimSpace(arg)
	for len(arg) > 0 {
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
		if i < 0 {
			tokens = append(tokens, arg)
			break
		}
		tokens = append(tokens, arg[:i])
		arg = strings.TrimSpace(arg[i+1:])
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