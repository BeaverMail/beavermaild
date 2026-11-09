// IMAP SEARCH program parsing (AND/OR/NOT/parentheses).
package imap

import (
	"strconv"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// searchParseStatus is the outcome of parsing a SEARCH, SORT or THREAD search program.
type searchParseStatus int

const (
	searchParsed searchParseStatus = iota
	searchSyntaxError
	searchBadCharset
)

// searchCharsets lists the charsets accepted for search strings, as sent in [BADCHARSET (...)].
// Strings are matched as UTF-8, of which US-ASCII is a subset.
const searchCharsets = "UTF-8 US-ASCII"

func supportedSearchCharset(name string) bool {
	return strings.EqualFold(name, "UTF-8") || strings.EqualFold(name, "US-ASCII")
}

// parseSearchCommand parses SEARCH arguments: [CHARSET name] search-program.
func parseSearchCommand(arg string) (mail.SearchExpr, searchParseStatus) {
	tokens := tokenizeSearchArg(arg)
	if len(tokens) >= 1 && strings.EqualFold(tokens[0], "CHARSET") {
		if len(tokens) < 2 {
			return mail.SearchExpr{}, searchSyntaxError
		}
		if !supportedSearchCharset(tokens[1]) {
			return mail.SearchExpr{}, searchBadCharset
		}
		tokens = tokens[2:]
	}
	return parseSearchTokens(tokens)
}

// parseSortSearch parses the "charset search-program" tail of SORT and THREAD (RFC 5256).
// The charset is mandatory there; a missing one is tolerated, and an empty program means ALL.
func parseSortSearch(arg string) (mail.SearchExpr, searchParseStatus) {
	tokens := tokenizeSearchArg(arg)
	hasCharset := len(tokens) > 0 && supportedSearchCharset(tokens[0])
	if hasCharset {
		tokens = tokens[1:]
	}
	if len(tokens) == 0 {
		return mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{All: true}}, searchParsed
	}
	expr, st := parseSearchTokens(tokens)
	if st != searchParsed && !hasCharset {
		// An unknown first atom followed by a valid program is an unsupported charset.
		if _, tail := parseSearchTokens(tokens[1:]); tail == searchParsed || len(tokens) == 1 {
			return mail.SearchExpr{}, searchBadCharset
		}
	}
	return expr, st
}

// parseSearchExpr parses a bare IMAP SEARCH criteria program (no charset).
func parseSearchExpr(arg string) (mail.SearchExpr, bool) {
	expr, st := parseSearchTokens(tokenizeSearchArg(arg))
	return expr, st == searchParsed
}

func parseSearchTokens(tokens []string) (mail.SearchExpr, searchParseStatus) {
	if len(tokens) == 0 {
		return mail.SearchExpr{}, searchSyntaxError
	}
	expr, rest, ok := parseSearchCriteriaList(tokens)
	if !ok || len(rest) != 0 {
		return mail.SearchExpr{}, searchSyntaxError
	}
	return expr, searchParsed
}

// parseSearchCriteriaList parses one-or-more search-keys ANDed together.
func parseSearchCriteriaList(tokens []string) (mail.SearchExpr, []string, bool) {
	var parts []*mail.SearchExpr
	for len(tokens) > 0 && tokens[0] != ")" {
		key, rest, ok := parseSearchKey(tokens)
		if !ok {
			return mail.SearchExpr{}, nil, false
		}
		parts = append(parts, key)
		tokens = rest
	}
	if len(parts) == 0 {
		return mail.SearchExpr{}, tokens, false
	}
	if len(parts) == 1 {
		return *parts[0], tokens, true
	}
	return mail.SearchExpr{Kind: mail.SearchExprAnd, And: parts}, tokens, true
}

// parseSearchKey parses a single search-key (atom, NOT, OR, or parenthesized list).
func parseSearchKey(tokens []string) (*mail.SearchExpr, []string, bool) {
	if len(tokens) == 0 {
		return nil, nil, false
	}
	switch strings.ToUpper(tokens[0]) {
	case "(":
		inner, rest, ok := parseSearchCriteriaList(tokens[1:])
		if !ok || len(rest) == 0 || rest[0] != ")" {
			return nil, nil, false
		}
		return &inner, rest[1:], true
	case "NOT":
		child, rest, ok := parseSearchKey(tokens[1:])
		if !ok {
			return nil, nil, false
		}
		return &mail.SearchExpr{Kind: mail.SearchExprNot, Not: child}, rest, true
	case "OR":
		left, rest, ok := parseSearchKey(tokens[1:])
		if !ok {
			return nil, nil, false
		}
		right, rest, ok := parseSearchKey(rest)
		if !ok {
			return nil, nil, false
		}
		return &mail.SearchExpr{
			Kind: mail.SearchExprOr,
			Or:   [2]*mail.SearchExpr{left, right},
		}, rest, true
	default:
		crit, n, ok := parseSearchAtom(tokens)
		if !ok {
			return nil, nil, false
		}
		return &mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: crit}, tokens[n:], true
	}
}

// parseSearchAtom parses one atomic SEARCH criterion and tokens consumed.
func parseSearchAtom(tokens []string) (mail.SearchCriteria, int, bool) {
	if len(tokens) == 0 {
		return mail.SearchCriteria{}, 0, false
	}
	key := strings.ToUpper(tokens[0])
	var c mail.SearchCriteria
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
		if len(tokens) < 2 {
			return mail.SearchCriteria{}, 0, false
		}
		uids, ok := parseSearchSeqSet(tokens[1])
		if !ok {
			return mail.SearchCriteria{}, 0, false
		}
		c.UIDs = uids
		return c, 2, true
	case "MODSEQ":
		// MODSEQ [entry-name entry-type-req] mod-sequence-valzer (RFC 7162). Mod-sequences are
		// kept per message, not per flag, so the optional entry is accepted and ignored.
		n := 2
		if len(tokens) >= 4 && !isDigits(tokens[1]) {
			switch strings.ToLower(tokens[2]) {
			case "priv", "shared", "all":
			default:
				return mail.SearchCriteria{}, 0, false
			}
			n = 4
		}
		if len(tokens) < n {
			return mail.SearchCriteria{}, 0, false
		}
		v, err := strconv.ParseUint(tokens[n-1], 10, 63)
		if err != nil {
			return mail.SearchCriteria{}, 0, false
		}
		c.ModSeq = &v
		return c, n, true
	case "FROM", "TO", "CC", "BCC", "SUBJECT", "TEXT", "BODY":
		if len(tokens) < 2 {
			return mail.SearchCriteria{}, 0, false
		}
		val := tokens[1]
		switch key {
		case "FROM":
			c.From = val
		case "TO":
			c.To = val
		case "CC":
			c.CC = val
		case "BCC":
			c.BCC = val
		case "SUBJECT":
			c.Subject = val
		case "TEXT":
			c.Text = val
		case "BODY":
			c.Body = val
		}
		if !searchAtomHasCriterion(c) {
			return mail.SearchCriteria{}, 0, false
		}
		return c, 2, true
	case "LARGER", "SMALLER":
		if len(tokens) < 2 {
			return mail.SearchCriteria{}, 0, false
		}
		n, err := strconv.ParseUint(tokens[1], 10, 32)
		if err != nil {
			return mail.SearchCriteria{}, 0, false
		}
		v := uint32(n)
		if key == "LARGER" {
			c.Larger = &v
		} else {
			c.Smaller = &v
		}
		if !searchAtomHasCriterion(c) {
			return mail.SearchCriteria{}, 0, false
		}
		return c, 2, true
	case "HEADER":
		if len(tokens) < 3 {
			return mail.SearchCriteria{}, 0, false
		}
		c.Headers = []mail.HeaderCriterion{{Field: tokens[1], Value: tokens[2]}}
		if !searchAtomHasCriterion(c) {
			return mail.SearchCriteria{}, 0, false
		}
		return c, 3, true
	case "SINCE", "BEFORE", "ON", "SENTSINCE", "SENTBEFORE", "SENTON":
		if len(tokens) < 2 {
			return mail.SearchCriteria{}, 0, false
		}
		t, ok := parseIMAPDate(tokens[1])
		if !ok {
			return mail.SearchCriteria{}, 0, false
		}
		switch key {
		case "SINCE":
			c.Since = &t
		case "BEFORE":
			c.Before = &t
		case "ON":
			c.On = &t
		case "SENTSINCE":
			c.SentSince = &t
		case "SENTBEFORE":
			c.SentBefore = &t
		case "SENTON":
			c.SentOn = &t
		}
		if !searchAtomHasCriterion(c) {
			return mail.SearchCriteria{}, 0, false
		}
		return c, 2, true
	case "KEYWORD", "UNKEYWORD":
		if len(tokens) < 2 {
			return mail.SearchCriteria{}, 0, false
		}
		if key == "KEYWORD" {
			c.Keyword = tokens[1]
		} else {
			c.Unkeyword = tokens[1]
		}
		if !searchAtomHasCriterion(c) {
			return mail.SearchCriteria{}, 0, false
		}
		return c, 2, true
	default:
		seqs, ok := parseSearchSeqSet(tokens[0])
		if !ok {
			return mail.SearchCriteria{}, 0, false
		}
		c.Seqs = seqs
		return c, 1, true
	}
	if !searchAtomHasCriterion(c) {
		return mail.SearchCriteria{}, 0, false
	}
	return c, 1, true
}

func searchAtomHasCriterion(c mail.SearchCriteria) bool {
	return c.All || c.Seen != nil || c.UIDs != nil || c.Seqs != nil || c.ModSeq != nil || c.Flagged != nil || c.Answered != nil ||
		c.Deleted != nil || c.Draft != nil || c.Recent != nil ||
		c.From != "" || c.To != "" || c.CC != "" || c.BCC != "" || c.Subject != "" ||
		c.Text != "" || c.Body != "" || len(c.Headers) > 0 ||
		c.Larger != nil || c.Smaller != nil ||
		c.Since != nil || c.Before != nil || c.On != nil ||
		c.SentSince != nil || c.SentBefore != nil || c.SentOn != nil ||
		c.Keyword != "" || c.Unkeyword != ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
