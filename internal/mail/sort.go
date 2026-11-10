// IMAP SORT (RFC 5256): ordered sequence numbers from search + sort keys.
package mail

import (
	"cmp"
	"context"
	"net/mail"
	"sort"
	"strings"
	"time"
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
	arrival int64
	date    time.Time
	from    string
	to      string
	cc      string
	subject string
	size    uint32
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
	var rows []sortRow
	pos := newSearchPos(msgs)
	for i, m := range msgs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pos.seq = uint32(i + 1)
		if !matchSearchExprOne(m, pos, &expr, load) {
			continue
		}
		rows = append(rows, sortRow{
			seq:    uint32(i + 1),
			fields: loadSortFields(m, load),
		})
	}
	// Rows start in sequence order and the sort is stable: exact ties keep mailbox order, even
	// under REVERSE (RFC 5256 section 3).
	sort.SliceStable(rows, func(i, j int) bool {
		for _, c := range crits {
			cmp := compareSortFields(rows[i].fields, rows[j].fields, c.Key)
			if c.Reverse {
				cmp = -cmp
			}
			if cmp != 0 {
				return cmp < 0
			}
		}
		return false
	})
	out := make([]uint32, len(rows))
	for i, r := range rows {
		out[i] = r.seq
	}
	return out, nil
}

func loadSortFields(m Message, load RawLoader) sortFields {
	f := sortFields{
		arrival: m.Meta.ReceivedAt,
		size:    m.Meta.Size,
		date:    time.Unix(m.Meta.ReceivedAt, 0),
	}
	if load == nil {
		return f
	}
	raw, err := load(m)
	if err != nil {
		return f
	}
	h := ParseMsgHeaders(raw)
	// i;ascii-casemap compares upper-cased ASCII.
	f.from = strings.ToUpper(firstAddrMailbox(h.From))
	f.to = strings.ToUpper(firstAddrMailbox(h.To))
	f.cc = strings.ToUpper(firstAddrMailbox(h.Cc))
	base, _ := BaseSubject(h.Subject)
	f.subject = strings.ToUpper(base)
	// DATE is the sent date; without a valid Date header it is the internal date (RFC 5256).
	if t, err := mail.ParseDate(h.Date); err == nil {
		f.date = t
	}
	return f
}

// firstAddrMailbox returns the local part (addr-mailbox) of the first address in a header value.
// A leading group ("name: a@b;") counts as an address whose mailbox is the group name, as in the
// IMAP ENVELOPE.
func firstAddrMailbox(value string) string {
	plain := strings.TrimSpace(stripAddressComments(value))
	if i := strings.IndexByte(plain, ':'); i > 0 && !strings.ContainsAny(plain[:i], "@<\",") {
		return strings.TrimSpace(plain[:i])
	}
	for _, v := range []string{value, plain} {
		if addrs, err := mail.ParseAddressList(v); err == nil && len(addrs) > 0 {
			local, _, _ := strings.Cut(addrs[0].Address, "@")
			return local
		}
	}
	return ""
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
	default:
		return 0
	}
}
