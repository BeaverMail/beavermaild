// IMAP SEARCH program tree evaluation (AND/OR/NOT/parentheses).
package mail

// SearchExprKind tags nodes in an IMAP SEARCH program.
type SearchExprKind int

const (
	SearchExprCrit SearchExprKind = iota
	SearchExprAnd
	SearchExprOr
	SearchExprNot
)

// SearchExpr is an IMAP SEARCH program tree (RFC 3501).
type SearchExpr struct {
	Kind SearchExprKind
	And  []*SearchExpr
	Or   [2]*SearchExpr
	Not  *SearchExpr
	Crit SearchCriteria
}

// MatchSearchExpr returns 1-based sequence numbers matching expr in msgs order.
func MatchSearchExpr(msgs []Message, expr SearchExpr) []uint32 {
	return MatchSearchExprWithLoader(msgs, expr, nil)
}

// MatchSearchExprWithLoader evaluates expr with optional raw loader for header/body criteria.
func MatchSearchExprWithLoader(msgs []Message, expr SearchExpr, load RawLoader) []uint32 {
	var out []uint32
	for i, m := range msgs {
		if !matchSearchExprOne(m, &expr, load) {
			continue
		}
		out = append(out, uint32(i+1))
	}
	return out
}

// MatchSearchUIDExprWithLoader returns UIDs matching expr.
func MatchSearchUIDExprWithLoader(msgs []Message, expr SearchExpr, load RawLoader) []uint32 {
	seqs := MatchSearchExprWithLoader(msgs, expr, load)
	out := make([]uint32, len(seqs))
	for i, seq := range seqs {
		out[i] = msgs[seq-1].UID
	}
	return out
}

func matchSearchExprOne(m Message, expr *SearchExpr, load RawLoader) bool {
	if expr == nil {
		return false
	}
	switch expr.Kind {
	case SearchExprCrit:
		return matchSearchOne(m, expr.Crit, load)
	case SearchExprAnd:
		for _, child := range expr.And {
			if !matchSearchExprOne(m, child, load) {
				return false
			}
		}
		return len(expr.And) > 0
	case SearchExprOr:
		return matchSearchExprOne(m, expr.Or[0], load) || matchSearchExprOne(m, expr.Or[1], load)
	case SearchExprNot:
		return !matchSearchExprOne(m, expr.Not, load)
	default:
		return false
	}
}
