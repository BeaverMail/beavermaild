// IMAP THREAD REFERENCES (RFC 5255): group messages by Message-ID links.
package mail

import (
	"sort"
)

type threadMember struct {
	seq     uint32
	arrival int64
	msgID   string
	headers MsgHeaders
}

// ThreadReferences groups matching messages into threads sorted by arrival within each thread.
func ThreadReferences(msgs []Message, expr SearchExpr, load RawLoader) [][]uint32 {
	var members []threadMember
	for i, m := range msgs {
		if !matchSearchExprOne(m, &expr, load) {
			continue
		}
		tm := threadMember{
			seq:     uint32(i + 1),
			arrival: m.Meta.ReceivedAt,
		}
		if load != nil {
			if raw, err := load(m); err == nil {
				tm.headers = ParseMsgHeaders(raw)
				tm.msgID = tm.headers.MessageID
			}
		}
		members = append(members, tm)
	}
	if len(members) == 0 {
		return nil
	}

	idToIdx := make(map[string]int, len(members))
	for i, m := range members {
		if m.msgID != "" {
			idToIdx[m.msgID] = i
		}
	}
	parent := make([]int, len(members))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}
	for i, m := range members {
		if p := findThreadParent(m.headers, idToIdx); p >= 0 {
			union(i, p)
		}
	}

	groups := make(map[int][]threadMember)
	for i, m := range members {
		root := find(i)
		groups[root] = append(groups[root], m)
	}

	threads := make([][]uint32, 0, len(groups))
	for _, g := range groups {
		sort.Slice(g, func(i, j int) bool {
			if g[i].arrival != g[j].arrival {
				return g[i].arrival < g[j].arrival
			}
			return g[i].seq < g[j].seq
		})
		nums := make([]uint32, len(g))
		for i, m := range g {
			nums[i] = m.seq
		}
		threads = append(threads, nums)
	}
	sort.Slice(threads, func(i, j int) bool {
		return threads[i][0] < threads[j][0]
	})
	return threads
}

// ThreadReferencesUIDs returns UID lists per thread.
func ThreadReferencesUIDs(msgs []Message, expr SearchExpr, load RawLoader) [][]uint32 {
	threads := ThreadReferences(msgs, expr, load)
	out := make([][]uint32, len(threads))
	for i, th := range threads {
		uids := make([]uint32, len(th))
		for j, seq := range th {
			uids[j] = msgs[seq-1].UID
		}
		out[i] = uids
	}
	return out
}

func findThreadParent(h MsgHeaders, idToIdx map[string]int) int {
	if h.InReplyTo != "" {
		if idx, ok := idToIdx[h.InReplyTo]; ok {
			return idx
		}
	}
	for i := len(h.References) - 1; i >= 0; i-- {
		id := h.References[i]
		if id == h.MessageID {
			continue
		}
		if idx, ok := idToIdx[id]; ok {
			return idx
		}
	}
	return -1
}
