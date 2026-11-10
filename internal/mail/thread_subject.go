// IMAP THREAD ORDEREDSUBJECT (RFC 5256 section 4).
package mail

import (
	"cmp"
	"context"
	"slices"
)

// ThreadOrderedSubjectContext groups the messages matching expr by base subject: each thread is
// its earliest message with the others as its children, in sent-date order, and threads are
// ordered by the date of their first message. Ties keep sequence order.
func ThreadOrderedSubjectContext(ctx context.Context, msgs []Message, expr SearchExpr, load RawLoader) ([]*ThreadNode, error) {
	rows, err := matchSortRows(ctx, msgs, expr, load)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(rows, func(a, b sortRow) int {
		return cmp.Or(compareSortFields(a.fields, b.fields, SortSubject), compareSortFields(a.fields, b.fields, SortDate))
	})
	type thread struct {
		first sortRow
		node  *ThreadNode
	}
	var threads []thread
	for i, r := range rows {
		if i > 0 && r.fields.subject == rows[i-1].fields.subject {
			root := threads[len(threads)-1].node
			root.Children = append(root.Children, &ThreadNode{Seq: r.seq})
			continue
		}
		threads = append(threads, thread{first: r, node: &ThreadNode{Seq: r.seq}})
	}
	slices.SortStableFunc(threads, func(a, b thread) int {
		return cmp.Or(compareSortFields(a.first.fields, b.first.fields, SortDate), cmp.Compare(a.first.seq, b.first.seq))
	})
	out := make([]*ThreadNode, len(threads))
	for i, t := range threads {
		out[i] = t.node
	}
	return out, nil
}
