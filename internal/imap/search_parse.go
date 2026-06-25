// IMAP SEARCH program parsing (AND/OR/NOT/parentheses).
package imap

import (
	"strconv"
	"strings"

	"github.com/BeaverMail/beaver/internal/mail"
)

// parseSearchExpr parses a full IMAP SEARCH criteria program.
func parseSearchExpr(arg string) (mail.SearchExpr, bool) {
	tokens := tokenizeSearchArg(strings.TrimSpace(arg))
	if len(tokens) == 0 {
		return mail.SearchExpr{}, false
	}
	expr, rest, ok := parseSearchCriteriaList(tokens)
	if !ok || len(rest) != 0 {
		return mail.SearchExpr{}, false
	}
	return expr, true
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
		lo, hi, ok := parseUIDSearchRange(tokens[1])
		if !ok {
			return mail.SearchCriteria{}, 0, false
		}
		c.UIDSet = true
		c.UIDMin = lo
		c.UIDMax = hi
		if !searchAtomHasCriterion(c) {
			return mail.SearchCriteria{}, 0, false
		}
		return c, 2, true
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
		return mail.SearchCriteria{}, 0, false
	}
	if !searchAtomHasCriterion(c) {
		return mail.SearchCriteria{}, 0, false
	}
	return c, 1, true
}

func searchAtomHasCriterion(c mail.SearchCriteria) bool {
	return c.All || c.Seen != nil || c.UIDSet || c.Flagged != nil || c.Answered != nil ||
		c.Deleted != nil || c.Draft != nil || c.Recent != nil ||
		c.From != "" || c.To != "" || c.CC != "" || c.BCC != "" || c.Subject != "" ||
		c.Text != "" || c.Body != "" || len(c.Headers) > 0 ||
		c.Larger != nil || c.Smaller != nil ||
		c.Since != nil || c.Before != nil || c.On != nil ||
		c.SentSince != nil || c.SentBefore != nil || c.SentOn != nil ||
		c.Keyword != "" || c.Unkeyword != ""
}
