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
	pos := newSearchPos(msgs)
	for i, m := range msgs {
		pos.seq = uint32(i + 1)
		if !matchSearchExprOne(m, pos, &expr, load) {
			continue
		}
		out = append(out, pos.seq)
	}
	return out
}

// UsesModSeq reports whether expr contains a MODSEQ criterion (RFC 7162: the SEARCH and SORT
// responses then carry the highest mod-sequence of the returned messages).
func (e *SearchExpr) UsesModSeq() bool {
	if e == nil {
		return false
	}
	switch e.Kind {
	case SearchExprCrit:
		return e.Crit.ModSeq != nil
	case SearchExprAnd:
		for _, child := range e.And {
			if child.UsesModSeq() {
				return true
			}
		}
		return false
	case SearchExprOr:
		return e.Or[0].UsesModSeq() || e.Or[1].UsesModSeq()
	case SearchExprNot:
		return e.Not.UsesModSeq()
	default:
		return false
	}
}

// HighestModSeq returns the largest per-message mod-sequence among the 1-based seqs of msgs.
func HighestModSeq(msgs []Message, seqs []uint32) uint64 {
	var highest uint64
	for _, seq := range seqs {
		if ms := msgs[seq-1].Meta.ModSeq; ms > highest {
			highest = ms
		}
	}
	return highest
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

func matchSearchExprOne(m Message, pos searchPos, expr *SearchExpr, load RawLoader) bool {
	if expr == nil {
		return false
	}
	switch expr.Kind {
	case SearchExprCrit:
		return matchSearchOne(m, pos, expr.Crit, load)
	case SearchExprAnd:
		for _, child := range expr.And {
			if !matchSearchExprOne(m, pos, child, load) {
				return false
			}
		}
		return len(expr.And) > 0
	case SearchExprOr:
		return matchSearchExprOne(m, pos, expr.Or[0], load) || matchSearchExprOne(m, pos, expr.Or[1], load)
	case SearchExprNot:
		return !matchSearchExprOne(m, pos, expr.Not, load)
	default:
		return false
	}
}
