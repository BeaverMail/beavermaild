// IMAP SEARCH program tree evaluation (AND/OR/NOT/parentheses).
package mail

import "context"

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
	out, _ := MatchSearchExprContext(context.Background(), msgs, expr, load)
	return out
}

// MatchSearchExprContext is MatchSearchExprWithLoader that stops with ctx.Err() once ctx is done.
func MatchSearchExprContext(ctx context.Context, msgs []Message, expr SearchExpr, load RawLoader) ([]uint32, error) {
	var out []uint32
	pos := newSearchPos(msgs)
	prepared := expr.withKeys()
	for i, m := range msgs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pos.seq = uint32(i + 1)
		if !matchSearchExprOne(m, pos, prepared, load) {
			continue
		}
		out = append(out, pos.seq)
	}
	return out, nil
}

// UsesModSeq reports whether expr contains a MODSEQ criterion (RFC 7162: the SEARCH and SORT
// responses then carry the highest mod-sequence of the returned messages).
func (e *SearchExpr) UsesModSeq() bool {
	return e.anyCrit(func(c *SearchCriteria) bool { return c.ModSeq != nil })
}

// FixPositions returns a copy of e with its message numbers resolved against msgs, the mailbox
// when the command was received (RFC 5267 4.3, from the RFC 3501 errata): a sequence set becomes the
// UIDs it named then. In a UID set, "n:*" stays open upward (new messages still match) and any
// other "*" becomes the largest UID then. Each message's match then depends on that message alone.
func (e *SearchExpr) FixPositions(msgs []Message) *SearchExpr {
	if e == nil {
		return nil
	}
	out := *e
	switch e.Kind {
	case SearchExprCrit:
		var largest uint32
		if len(msgs) > 0 {
			largest = msgs[len(msgs)-1].UID
		}
		if e.Crit.Seqs != nil {
			uids := []SeqRange{} // non-nil: a set that named nothing still matches nothing
			for i, m := range msgs {
				if seqRangesContain(e.Crit.Seqs, uint32(i+1), uint32(len(msgs))) {
					uids = append(uids, SeqRange{m.UID, m.UID})
				}
			}
			out.Crit.Seqs, out.Crit.UIDs = nil, uids
		} else if e.Crit.UIDs != nil {
			out.Crit.UIDs = make([]SeqRange, len(e.Crit.UIDs))
			for i, r := range e.Crit.UIDs {
				switch {
				case r.Lo == 0 && r.Hi == 0:
					r = SeqRange{largest, largest}
				case r.Hi == 0 && r.Lo <= largest, r.Lo == 0 && r.Hi <= largest:
					r = SeqRange{max(r.Lo, r.Hi), ^uint32(0)}
				case r.Hi == 0, r.Lo == 0:
					r = SeqRange{largest, max(r.Lo, r.Hi)}
				}
				out.Crit.UIDs[i] = r
			}
		}
	case SearchExprAnd:
		out.And = make([]*SearchExpr, len(e.And))
		for i, child := range e.And {
			out.And[i] = child.FixPositions(msgs)
		}
	case SearchExprOr:
		out.Or = [2]*SearchExpr{e.Or[0].FixPositions(msgs), e.Or[1].FixPositions(msgs)}
	case SearchExprNot:
		out.Not = e.Not.FixPositions(msgs)
	}
	return &out
}

// anyCrit reports whether some criterion node of expr satisfies pred.
func (e *SearchExpr) anyCrit(pred func(*SearchCriteria) bool) bool {
	if e == nil {
		return false
	}
	switch e.Kind {
	case SearchExprCrit:
		return pred(&e.Crit)
	case SearchExprAnd:
		for _, child := range e.And {
			if child.anyCrit(pred) {
				return true
			}
		}
		return false
	case SearchExprOr:
		return e.Or[0].anyCrit(pred) || e.Or[1].anyCrit(pred)
	case SearchExprNot:
		return e.Not.anyCrit(pred)
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

// withKeys returns a copy of the tree with every criterion's text keys folded; the tree itself is
// left alone, as it may be shared (a saved CONTEXT search).
func (e *SearchExpr) withKeys() *SearchExpr {
	if e == nil {
		return nil
	}
	out := *e
	out.Crit = e.Crit.withKeys()
	out.And = make([]*SearchExpr, len(e.And))
	for i, child := range e.And {
		out.And[i] = child.withKeys()
	}
	out.Or = [2]*SearchExpr{e.Or[0].withKeys(), e.Or[1].withKeys()}
	out.Not = e.Not.withKeys()
	return &out
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
