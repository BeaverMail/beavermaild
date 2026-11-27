// IMAP SORT (RFC 5256): ordered sequence numbers from search + sort keys.
package mail

import (
	"cmp"
	"context"
	"sort"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/internal/rfc5322"
)

// SortKey is one RFC 5256 sort criterion.
type SortKey int

const (
	SortArrival SortKey = iota
	SortCC
	SortDate
	SortFrom
	SortSize
	SortSubject
	SortTo
	SortDisplayFrom // RFC 5957
	SortDisplayTo
)

// SortCriterion is one sort key; Reverse applies to that key only (RFC 5256 "REVERSE key").
type SortCriterion struct {
	Key     SortKey
	Reverse bool
}

type sortRow struct {
	seq    uint32
	fields sortFields
}

type sortFields struct {
	arrival                int64
	date                   time.Time
	from                   string
	to                     string
	cc                     string
	subject                string
	size                   uint32
	displayFrom, displayTo string // RFC 5957 display values
}

// SortMessages returns 1-based sequence numbers matching expr, sorted by crits.
func SortMessages(msgs []Message, crits []SortCriterion, expr SearchExpr, load RawLoader) []uint32 {
	out, _ := SortMessagesContext(context.Background(), msgs, crits, expr, load)
	return out
}

// SortMessagesContext is SortMessages that stops with ctx.Err() once ctx is done.
func SortMessagesContext(ctx context.Context, msgs []Message, crits []SortCriterion, expr SearchExpr, load RawLoader) ([]uint32, error) {
	if len(crits) == 0 {
		return nil, nil
	}
	rows, err := matchSortRows(ctx, msgs, expr, load)
	if err != nil {
		return nil, err
	}
	// Rows start in sequence order and the sort is stable: exact ties keep mailbox order, even
	// under REVERSE (RFC 5256 section 3).
	sort.SliceStable(rows, func(i, j int) bool {
		return compareSortCrits(rows[i].fields, rows[j].fields, crits) < 0
	})
	out := make([]uint32, len(rows))
	for i, r := range rows {
		out[i] = r.seq
	}
	return out, nil
}

// matchSortRows returns the sort fields of the messages matching expr, in sequence order.
func matchSortRows(ctx context.Context, msgs []Message, expr SearchExpr, load RawLoader) ([]sortRow, error) {
	var rows []sortRow
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
		rows = append(rows, sortRow{seq: uint32(i + 1), fields: loadSortFields(m, load)})
	}
	return rows, nil
}

// SortFields holds one message's sort values. They never change for a stored message, so a
// caller keeping a sorted result can load them once and insert new members with CompareSort.
type SortFields struct{ f sortFields }

// LoadSortFields reads m's sort values (its header, through load).
func LoadSortFields(m Message, load RawLoader) SortFields { return SortFields{loadSortFields(m, load)} }

// CompareSort orders a and b by crits as SORT does; exact ties (0) keep mailbox order.
func CompareSort(a, b SortFields, crits []SortCriterion) int {
	return compareSortCrits(a.f, b.f, crits)
}

func compareSortCrits(a, b sortFields, crits []SortCriterion) int {
	for _, c := range crits {
		r := compareSortFields(a, b, c.Key)
		if c.Reverse {
			r = -r
		}
		if r != 0 {
			return r
		}
	}
	return 0
}

func loadSortFields(m Message, load RawLoader) sortFields {
	f := sortFields{
		arrival: m.Meta.ReceivedAt,
		size:    RFC822Size(m.Meta), // RFC 5256 SIZE is RFC822.SIZE
		date:    time.Unix(m.Meta.ReceivedAt, 0),
	}
	if load == nil {
		return f
	}
	raw, ok := loadHeader(load, m)
	if !ok {
		return f
	}
	h := ParseMsgHeaders(raw)
	f.from = unicodeCasemap(firstAddrMailbox(h.From))
	f.to = unicodeCasemap(firstAddrMailbox(h.To))
	f.cc = unicodeCasemap(firstAddrMailbox(h.Cc))
	f.displayFrom = unicodeCasemap(firstAddrDisplay(h.From))
	f.displayTo = unicodeCasemap(firstAddrDisplay(h.To))
	base, _ := BaseSubject(h.Subject)
	f.subject = unicodeCasemap(base)
	// DATE is the sent date; without a valid Date header it is the internal date (RFC 5256).
	if t, err := rfc5322.ParseDate(h.Date); err == nil {
		f.date = t
	}
	return f
}

func compareSortFields(a, b sortFields, key SortKey) int {
	switch key {
	case SortArrival:
		return cmp.Compare(a.arrival, b.arrival)
	case SortSize:
		return cmp.Compare(a.size, b.size)
	case SortDate:
		return a.date.Compare(b.date)
	case SortFrom:
		return strings.Compare(a.from, b.from)
	case SortTo:
		return strings.Compare(a.to, b.to)
	case SortCC:
		return strings.Compare(a.cc, b.cc)
	case SortSubject:
		return strings.Compare(a.subject, b.subject)
	case SortDisplayFrom:
		return strings.Compare(a.displayFrom, b.displayFrom)
	case SortDisplayTo:
		return strings.Compare(a.displayTo, b.displayTo)
	default:
		return 0
	}
}
