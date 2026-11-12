// IMAP THREAD REFERENCES (RFC 5256 section 4).
package mail

import (
	"context"
	"net/mail"
	"slices"
	"strconv"
	"time"
)

// ThreadNode is one node of a thread tree: a message (Seq > 0) or a dummy that only groups its
// children (Seq == 0, for a referenced message that is missing or a shared subject).
type ThreadNode struct {
	Seq      uint32
	Children []*ThreadNode
}

// threadContainer is a node while the threads are built.
type threadContainer struct {
	seq      uint32 // 0: dummy
	date     time.Time
	subject  string
	parent   *threadContainer
	children []*threadContainer
}

// ThreadReferences threads the messages matching expr; see ThreadReferencesContext.
func ThreadReferences(msgs []Message, expr SearchExpr, load RawLoader) []*ThreadNode {
	out, _ := ThreadReferencesContext(context.Background(), msgs, expr, load)
	return out
}

// ThreadReferencesContext runs the REFERENCES algorithm over the messages matching expr and
// returns the thread trees in order. It stops with ctx.Err() once ctx is done.
func ThreadReferencesContext(ctx context.Context, msgs []Message, expr SearchExpr, load RawLoader) ([]*ThreadNode, error) {
	ids := map[string]*threadContainer{}
	byID := func(id string) *threadContainer {
		c := ids[id]
		if c == nil {
			c = &threadContainer{}
			ids[id] = c
		}
		return c
	}
	var all []*threadContainer
	pos := newSearchPos(msgs)
	for i, m := range msgs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pos.seq = uint32(i + 1)
		if !matchSearchExprOne(m, pos, &expr, load) {
			continue
		}
		var h MsgHeaders
		if load != nil {
			if raw, ok := loadHeader(load, m); ok {
				h = ParseMsgHeaders(raw)
			}
		}
		date := time.Unix(m.Meta.ReceivedAt, 0)
		if t, err := mail.ParseDate(h.Date); err == nil {
			date = t
		}

		// (1) The message's container: a missing or duplicate Message-ID gets a unique one.
		id := h.MessageID
		if id == "" || (ids[id] != nil && ids[id].seq != 0) {
			id = "\x00" + strconv.Itoa(i)
		}
		c := byID(id)
		c.seq, c.date, c.subject = uint32(i+1), date, h.Subject
		all = append(all, c)

		// (1A) Link the references in order, parent before child, without loops or re-parenting.
		refs := h.References
		if len(refs) == 0 {
			if irt := ParseMessageIDList(h.InReplyTo); len(irt) > 0 {
				refs = irt[:1]
			}
		}
		var prev *threadContainer
		for _, ref := range refs {
			rc := byID(ref)
			if prev != nil && rc.parent == nil && !isThreadAncestor(rc, prev) {
				link(prev, rc)
			}
			prev = rc
		}
		// (1B) The last reference is the message's parent, replacing any earlier parent.
		if prev != nil && prev != c && isThreadAncestor(c, prev) {
			prev = nil
		}
		if c.parent != nil {
			unlink(c)
		}
		if prev != nil && prev != c {
			link(prev, c)
		}
	}

	// (2) Root set; (4) prune dummies.
	var roots []*threadContainer
	for _, c := range ids {
		if c.parent == nil {
			roots = append(roots, c)
		}
	}
	roots = pruneThreads(roots, true)
	for _, r := range roots {
		r.parent = nil
	}

	// (5) Sort the root set by sent date (a dummy uses its first child's date).
	for _, r := range roots {
		sortThreadChildren(r)
	}
	sortThreadSiblings(roots)

	// (6) Group the root set by base subject.
	roots = groupThreadsBySubject(roots)

	// (7) Sort children again: merges may have appended out of order.
	for _, r := range roots {
		sortThreadChildren(r)
	}
	out := make([]*ThreadNode, len(roots))
	for i, r := range roots {
		out[i] = r.node()
	}
	return out, nil
}

func link(parent, child *threadContainer) {
	child.parent = parent
	parent.children = append(parent.children, child)
}

func unlink(c *threadContainer) {
	p := c.parent
	p.children = slices.DeleteFunc(p.children, func(x *threadContainer) bool { return x == c })
	c.parent = nil
}

// isThreadAncestor reports whether a is b or one of b's ancestors.
func isThreadAncestor(a, b *threadContainer) bool {
	for x := b; x != nil; x = x.parent {
		if x == a {
			return true
		}
	}
	return false
}

// pruneThreads removes empty dummies and promotes the children of dummies, except a root dummy
// with several children, which stays to group them.
func pruneThreads(level []*threadContainer, root bool) []*threadContainer {
	var out []*threadContainer
	for _, c := range level {
		c.children = pruneThreads(c.children, false)
		for _, ch := range c.children {
			ch.parent = c
		}
		switch {
		case c.seq != 0:
			out = append(out, c)
		case len(c.children) == 0:
		case root && len(c.children) > 1:
			out = append(out, c)
		default:
			out = append(out, c.children...)
		}
	}
	return out
}

// threadDate is a node's sent date; a dummy takes its first child's date after sorting.
func (c *threadContainer) threadDate() (time.Time, uint32) {
	if c.seq == 0 && len(c.children) > 0 {
		return c.children[0].threadDate()
	}
	return c.date, c.seq
}

func sortThreadSiblings(level []*threadContainer) {
	slices.SortStableFunc(level, func(a, b *threadContainer) int {
		da, sa := a.threadDate()
		db, sb := b.threadDate()
		if n := da.Compare(db); n != 0 {
			return n
		}
		return int(sa) - int(sb)
	})
}

func sortThreadChildren(c *threadContainer) {
	for _, ch := range c.children {
		sortThreadChildren(ch)
	}
	sortThreadSiblings(c.children)
}

// threadSubject is the subject a root groups by: its own, or its first child's for a dummy.
func (c *threadContainer) threadSubject() (string, bool) {
	if c.seq == 0 && len(c.children) > 0 {
		return c.children[0].threadSubject()
	}
	return BaseSubject(c.subject)
}

// groupThreadsBySubject merges roots that share a base subject (RFC 5256 step 6).
func groupThreadsBySubject(roots []*threadContainer) []*threadContainer {
	// (6A) One root per subject: a dummy beats a message, a non-reply beats a reply.
	table := map[string]*threadContainer{}
	for _, r := range roots {
		subj, reply := r.threadSubject()
		if subj == "" {
			continue
		}
		old := table[subj]
		_, oldReply := old.subjectOrEmpty()
		if old == nil || (r.seq == 0 && old.seq != 0) || (oldReply && !reply) {
			table[subj] = r
		}
	}
	// (6B) Merge every other root with the table one.
	var out []*threadContainer
	placeholder := map[*threadContainer]*threadContainer{} // table root -> dummy that took its place
	for _, r := range roots {
		if r.parent != nil {
			// Already merged under a dummy created for it: the dummy goes here.
			if d := placeholder[r]; d != nil {
				out = append(out, d)
			}
			continue
		}
		subj, reply := r.threadSubject()
		t := table[subj]
		if subj == "" || t == nil || t == r {
			out = append(out, r)
			continue
		}
		_, tReply := t.threadSubject()
		switch {
		case t.seq == 0 && r.seq == 0:
			for _, ch := range r.children {
				link(t, ch)
			}
		case t.seq == 0:
			link(t, r)
		case reply && !tReply:
			link(t, r)
		default:
			d := &threadContainer{}
			if i := slices.Index(out, t); i >= 0 {
				out[i] = d
			} else {
				placeholder[t] = d
			}
			table[subj] = d
			link(d, t)
			link(d, r)
		}
	}
	return out
}

func (c *threadContainer) subjectOrEmpty() (string, bool) {
	if c == nil {
		return "", false
	}
	return c.threadSubject()
}

func (c *threadContainer) node() *ThreadNode {
	n := &ThreadNode{Seq: c.seq}
	for _, ch := range c.children {
		n.Children = append(n.Children, ch.node())
	}
	return n
}
