// IMAP SORT (RFC 5256): ordered sequence numbers from search + sort keys.
package mail

import (
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

type sortRow struct {
	seq    uint32
	fields sortFields
}

type sortFields struct {
	arrival int64
	date    time.Time
	hasDate bool
	from    string
	to      string
	cc      string
	subject string
	size    uint32
}

// SortMessages returns 1-based sequence numbers matching expr, sorted by keys.
func SortMessages(msgs []Message, keys []SortKey, reverse bool, expr SearchExpr, load RawLoader) []uint32 {
	if len(keys) == 0 {
		return nil
	}
	var rows []sortRow
	for i, m := range msgs {
		if !matchSearchExprOne(m, &expr, load) {
			continue
		}
		rows = append(rows, sortRow{
			seq:    uint32(i + 1),
			fields: loadSortFields(m, load),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		for _, key := range keys {
			cmp := compareSortFields(rows[i].fields, rows[j].fields, key)
			if cmp != 0 {
				if reverse {
					return cmp > 0
				}
				return cmp < 0
			}
		}
		if reverse {
			return rows[i].seq > rows[j].seq
		}
		return rows[i].seq < rows[j].seq
	})
	out := make([]uint32, len(rows))
	for i, r := range rows {
		out[i] = r.seq
	}
	return out
}

// SortUIDs returns UIDs in SORT order.
func SortUIDs(msgs []Message, keys []SortKey, reverse bool, expr SearchExpr, load RawLoader) []uint32 {
	seqs := SortMessages(msgs, keys, reverse, expr, load)
	out := make([]uint32, len(seqs))
	for i, seq := range seqs {
		out[i] = msgs[seq-1].UID
	}
	return out
}

func loadSortFields(m Message, load RawLoader) sortFields {
	f := sortFields{
		arrival: m.Meta.ReceivedAt,
		size:    m.Meta.Size,
	}
	if load == nil {
		return f
	}
	raw, err := load(m)
	if err != nil {
		return f
	}
	h := ParseMsgHeaders(raw)
	f.from = strings.ToLower(h.From)
	f.to = strings.ToLower(h.To)
	f.cc = strings.ToLower(h.Cc)
	f.subject = strings.ToLower(h.Subject)
	if h.Date != "" {
		if t, err := mail.ParseDate(h.Date); err == nil {
			f.date = t.UTC()
			f.hasDate = true
		}
	}
	return f
}

func compareSortFields(a, b sortFields, key SortKey) int {
	switch key {
	case SortArrival:
		return compareInt64(a.arrival, b.arrival)
	case SortSize:
		if a.size < b.size {
			return -1
		}
		if a.size > b.size {
			return 1
		}
		return 0
	case SortDate:
		if !a.hasDate && !b.hasDate {
			return 0
		}
		if !a.hasDate {
			return -1
		}
		if !b.hasDate {
			return 1
		}
		if a.date.Before(b.date) {
			return -1
		}
		if a.date.After(b.date) {
			return 1
		}
		return 0
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

func compareInt64(a, b int64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
