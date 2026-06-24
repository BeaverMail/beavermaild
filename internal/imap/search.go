// IMAP SEARCH argument parsing.
package imap

import (
	"strconv"
	"strings"

	"github.com/BeaverMail/beaver/internal/mail"
)

// parseSearchCriteria parses SEARCH filters (ALL, flag criteria, UID ranges).
func parseSearchCriteria(arg string) (mail.SearchCriteria, bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return mail.SearchCriteria{}, false
	}
	var c mail.SearchCriteria
	tokens := strings.Fields(strings.ToUpper(arg))
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
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
		default:
			return mail.SearchCriteria{}, false
		}
	}
	if !c.All && c.Seen == nil && !c.UIDSet && c.Flagged == nil && c.Answered == nil &&
		c.Deleted == nil && c.Draft == nil && c.Recent == nil {
		return mail.SearchCriteria{}, false
	}
	return c, true
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
