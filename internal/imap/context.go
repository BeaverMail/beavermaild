// IMAP CONTEXT=SEARCH and CONTEXT=SORT (RFC 5267): SEARCH/SORT RETURN (UPDATE) keeps a result
// up to date with ESEARCH ADDTO/REMOVEFROM until CANCELUPDATE or the mailbox is deselected.
package imap

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
)

// maxSearchContexts caps the updating contexts of one session; more get NOUPDATE.
const maxSearchContexts = 8

// searchContext is one updating SEARCH or SORT result.
type searchContext struct {
	tag    string
	byUID  bool
	sorted bool
	crits  []mail.SortCriterion
	expr   mail.SearchExpr
	result []uint32                   // member UIDs in result order
	seen   map[uint32]contextEntry    // every message evaluated, by UID
	fetch  *fetchItems                // UPDATE (fetch-att): sent for each new message joining (RFC 5465 7)
	keys   map[uint32]mail.SortFields // SORT: each member's sort values, read once
}

type contextEntry struct {
	meta storage.EmailMeta
	in   bool
}

// hasSearchContext reports whether tag already names an updating context (a reused tag is BAD).
func (s *session) hasSearchContext(tag string) bool {
	for _, c := range s.contexts {
		if c.tag == tag {
			return true
		}
	}
	return false
}

// addSearchContext starts updating the result seqs of command tag (crits nil for SEARCH).
func (s *session) addSearchContext(tag string, byUID bool, crits []mail.SortCriterion, expr mail.SearchExpr, seqs []uint32, fetch *fetchItems) error {
	if len(s.contexts) >= maxSearchContexts {
		return s.untagged("NO [NOUPDATE " + quoteIMAPString(tag) + "] too many updating contexts")
	}
	// Message numbers mean the messages they named now: a later expunge or arrival renumbers the
	// mailbox but changes no result (RFC 5267 4.3).
	c := &searchContext{tag: tag, byUID: byUID, sorted: crits != nil, crits: crits, expr: *expr.FixPositions(s.messages),
		seen: make(map[uint32]contextEntry, len(s.messages)), fetch: fetch}
	for _, m := range s.messages {
		c.seen[m.UID] = contextEntry{meta: m.Meta}
	}
	for _, seq := range seqs {
		uid := s.messages[seq-1].UID
		c.result = append(c.result, uid)
		c.seen[uid] = contextEntry{meta: s.messages[seq-1].Meta, in: true}
	}
	s.contexts = append(s.contexts, c)
	return nil
}

// cmdCancelUpdate ends the updating contexts named by the quoted tags in arg.
func (s *session) cmdCancelUpdate(tag, arg string) error {
	if !s.selected { // command-select (RFC 5267 5)
		return s.tagged(tag, "NO not selected")
	}
	rest := strings.TrimSpace(arg)
	if rest == "" {
		return s.tagged(tag, "BAD CANCELUPDATE syntax")
	}
	for rest != "" {
		name, tail, ok := parseQuoted(rest)
		if !ok {
			return s.tagged(tag, "BAD CANCELUPDATE syntax")
		}
		for i, c := range s.contexts {
			if c.tag == name {
				s.contexts = append(s.contexts[:i], s.contexts[i+1:]...)
				break
			}
		}
		rest = strings.TrimLeft(tail, " ")
	}
	return s.tagged(tag, "OK CANCELUPDATE completed")
}

// contextsExpunge sends REMOVEFROM for the message at seq leaving every result: RFC 5267 4.3.4
// wants it before the expunge notification.
func (s *session) contextsExpunge(seq int, uid uint32) error {
	for _, c := range s.contexts {
		e, ok := c.seen[uid]
		delete(c.seen, uid)
		delete(c.keys, uid)
		if !ok || !e.in {
			continue
		}
		for i, u := range c.result {
			if u == uid {
				c.result = append(c.result[:i], c.result[i+1:]...)
				val := uint32(seq)
				if c.byUID {
					val = uid
				}
				if err := s.untagged(c.change("REMOVEFROM", [][2]uint32{{c.position(i + 1), val}})); err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}

// refreshContexts re-evaluates every updating result against the session's message list and
// reports what joined (ADDTO) or left (REMOVEFROM) it.
func (s *session) refreshContexts(ctx context.Context) error {
	if !s.selected {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	load := s.rawOpener(ctx)
	for _, c := range s.contexts {
		if err := s.refreshContext(ctx, c, load); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) refreshContext(ctx context.Context, c *searchContext, load mail.RawLoader) error {
	var dirty []int
	arrived := map[uint32]bool{} // messages this context never saw: new, not flag changes
	for i, m := range s.messages {
		if _, ok := c.seen[m.UID]; !ok {
			arrived[m.UID] = true
		}
		if e, ok := c.seen[m.UID]; !ok || !messageMetaEqual(e.meta, m.Meta) {
			dirty = append(dirty, i)
		}
	}
	// With positions fixed at creation, a message's match depends on that message alone: only
	// new or changed ones are evaluated, never the whole mailbox again.
	for _, i := range dirty {
		m := s.messages[i]
		seqs, err := mail.MatchSearchExprContext(ctx, s.messages[i:i+1], c.expr, load)
		if err != nil {
			return err
		}
		c.seen[m.UID] = contextEntry{meta: m.Meta, in: len(seqs) > 0}
	}
	if len(dirty) == 0 {
		return nil
	}
	if len(c.seen) > len(s.messages) { // drop messages gone without an expunge notification
		live := make(map[uint32]bool, len(s.messages))
		for _, m := range s.messages {
			live[m.UID] = true
		}
		for uid := range c.seen {
			if !live[uid] {
				delete(c.seen, uid)
				delete(c.keys, uid)
			}
		}
	}

	seqOf := make(map[uint32]uint32, len(s.messages))
	for i, m := range s.messages {
		seqOf[m.UID] = uint32(i + 1)
	}
	val := func(uid uint32) uint32 {
		if c.byUID {
			return uid
		}
		return seqOf[uid]
	}
	var removed [][2]uint32
	inResult := make(map[uint32]bool, len(c.result))
	kept := c.result[:0]
	for _, uid := range c.result {
		if c.seen[uid].in {
			kept = append(kept, uid)
			inResult[uid] = true
			continue
		}
		removed = append(removed, [2]uint32{c.position(len(kept) + 1), val(uid)})
	}
	c.result = kept
	var members []mail.Message
	added := false
	for _, m := range s.messages {
		if c.seen[m.UID].in {
			members = append(members, m)
			added = added || !inResult[m.UID]
		}
	}
	var adds [][2]uint32
	if added {
		var next []uint32
		if c.sorted {
			var err error
			if next, err = c.insertSorted(ctx, members, inResult, load); err != nil {
				return err
			}
		} else {
			next = make([]uint32, 0, len(members))
			for _, m := range members {
				next = append(next, m.UID)
			}
		}
		for i, uid := range next {
			if !inResult[uid] {
				adds = append(adds, [2]uint32{c.position(i + 1), val(uid)})
			}
		}
		c.result = next
	}
	if len(removed) > 0 {
		if err := s.untagged(c.change("REMOVEFROM", removed)); err != nil {
			return err
		}
	}
	if len(adds) == 0 {
		return nil
	}
	// RFC 5465 7: EXISTS, then the FETCH of each new message, then the ADDTO; none for a message
	// that joins because its flags changed.
	if c.fetch != nil {
		for i, m := range s.messages {
			if arrived[m.UID] && c.seen[m.UID].in && !inResult[m.UID] {
				if err := s.writeFetch(ctx, i+1, m, *c.fetch, c.byUID); err != nil {
					return err
				}
			}
		}
	}
	return s.untagged(c.change("ADDTO", adds))
}

// insertSorted puts the members not yet in the SORT result at their place, by binary search on
// sort values kept per member: each message's header is read once for the context's life, not
// once per arrival (a sender could otherwise make every delivery re-read the whole result).
func (c *searchContext) insertSorted(ctx context.Context, members []mail.Message, inResult map[uint32]bool, load mail.RawLoader) ([]uint32, error) {
	if c.keys == nil {
		c.keys = make(map[uint32]mail.SortFields, len(members))
	}
	for _, m := range members {
		if _, ok := c.keys[m.UID]; !ok {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			c.keys[m.UID] = mail.LoadSortFields(m, load)
		}
	}
	order := func(a, b uint32) int {
		if r := mail.CompareSort(c.keys[a], c.keys[b], c.crits); r != 0 {
			return r
		}
		return cmp.Compare(a, b) // exact ties keep mailbox order, as SORT does
	}
	next := c.result
	for _, m := range members {
		if !inResult[m.UID] {
			i, _ := slices.BinarySearchFunc(next, m.UID, order)
			next = slices.Insert(next, i, m.UID)
		}
	}
	return next, nil
}

// position is the context position RFC 5267 4.3.3 sends: the result index for SORT, 0 for
// SEARCH (whose results stay in mailbox order).
func (c *searchContext) position(pos int) uint32 {
	if c.sorted {
		return uint32(pos)
	}
	return 0
}

// change formats an ESEARCH ADDTO or REMOVEFROM response from (position, number) pairs. SEARCH
// sends one position-0 set; SORT one pair per message, as positions shift with each.
func (c *searchContext) change(kind string, items [][2]uint32) string {
	var b strings.Builder
	b.WriteString("ESEARCH (TAG " + quoteIMAPString(c.tag) + ")")
	if c.byUID {
		b.WriteString(" UID")
	}
	b.WriteString(" " + kind + " (")
	if !c.sorted {
		nums := make([]uint32, len(items))
		for i, it := range items {
			nums[i] = it[1]
		}
		b.WriteString("0 " + formatUIDSet(nums) + ")")
		return b.String()
	}
	for i, it := range items {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(strconv.FormatUint(uint64(it[0]), 10) + " " + strconv.FormatUint(uint64(it[1]), 10))
	}
	return b.String() + ")"
}
