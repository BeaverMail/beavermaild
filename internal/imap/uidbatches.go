// IMAP UIDBATCHES (RFC 10022): split the selected mailbox into UID ranges of a given message
// count, newest first.
package imap

import (
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// uidBatchesMin is the smallest batch size a server must accept (RFC 10022 3.1.3.2).
const uidBatchesMin = 500

// uidBatchesTracked bounds the distinct UIDBATCHES requests remembered per selection.
const uidBatchesTracked = 64

// uidBatchesReq is one answered UIDBATCHES request and the mailbox state it was answered on.
type uidBatchesReq struct {
	size, first, last int
	count             int    // messages in the mailbox then
	maxUID            uint32 // highest UID then (0 when empty)
}

// stale reports whether the mailbox changed enough since r to allow resending it (RFC 10022
// 3.1.1): more than size/2 messages expunged or more than size/2 new ones.
func (s *session) stale(r uidBatchesReq) bool {
	newer := len(s.messages) - sort.Search(len(s.messages), func(i int) bool { return s.messages[i].UID > r.maxUID })
	expunged := r.count - (len(s.messages) - newer)
	return 2*newer > r.size || 2*expunged > r.size
}

// allowUIDBatches records the request and reports whether it may run: an identical request is
// refused until the mailbox changed by more than half a batch (RFC 10022 3.1.1, 6); selecting a
// mailbox clears the record. Distinct requests (other sizes or batch ranges, as 3.1.5 suggests
// for paging) are allowed up to uidBatchesTracked per selection.
func (s *session) allowUIDBatches(size, first, last int) bool {
	cur := uidBatchesReq{size: size, first: first, last: last, count: len(s.messages)}
	if n := len(s.messages); n > 0 {
		cur.maxUID = s.messages[n-1].UID
	}
	for i, r := range s.uidBatches {
		if r.size == size && r.first == first && r.last == last {
			if !s.stale(r) {
				return false
			}
			s.uidBatches[i] = cur
			return true
		}
	}
	if len(s.uidBatches) >= uidBatchesTracked {
		s.uidBatches = slices.DeleteFunc(s.uidBatches, s.stale)
		if len(s.uidBatches) >= uidBatchesTracked {
			return false
		}
	}
	s.uidBatches = append(s.uidBatches, cur)
	return true
}

// cmdUIDBatches answers "UIDBATCHES size [first:last]" with one high:low UID range per batch of
// size messages, batch 1 holding the newest; first:last limits the reply to those batches.
func (s *session) cmdUIDBatches(tag, arg string) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	f := strings.Fields(arg)
	if len(f) < 1 || len(f) > 2 {
		return s.tagged(tag, "BAD UIDBATCHES syntax")
	}
	size, ok := parseNZNumber(f[0])
	if !ok {
		return s.tagged(tag, "BAD UIDBATCHES syntax")
	}
	first, last := 1, math.MaxInt
	if len(f) == 2 {
		lo, hi, found := strings.Cut(f[1], ":")
		a, okA := parseNZNumber(lo)
		b, okB := parseNZNumber(hi)
		if !found || !okA || !okB {
			return s.tagged(tag, "BAD UIDBATCHES syntax")
		}
		if a > b {
			return s.tagged(tag, "BAD [CLIENTBUG] invalid batch range")
		}
		first, last = a, b
	}
	if size < uidBatchesMin {
		return s.tagged(tag, "NO [TOOFEW] minimum batch size is "+strconv.Itoa(uidBatchesMin))
	}
	if !s.allowUIDBatches(size, first, last) {
		return s.tagged(tag, "NO [LIMIT] mailbox unchanged since the same UIDBATCHES")
	}
	var b strings.Builder
	b.WriteString("UIDBATCHES (TAG " + quoteIMAPString(tag) + ")")
	n := 0
	for hi, batch := len(s.messages)-1, 1; hi >= 0 && batch <= last; hi, batch = hi-size, batch+1 {
		if batch < first {
			continue
		}
		lo := max(hi-size+1, 0)
		if n > 0 {
			b.WriteByte(',')
		} else {
			b.WriteByte(' ')
		}
		n++
		b.WriteString(strconv.FormatUint(uint64(s.messages[hi].UID), 10) + ":" + strconv.FormatUint(uint64(s.messages[lo].UID), 10))
	}
	if err := s.untagged(b.String()); err != nil {
		return err
	}
	return s.tagged(tag, "OK UIDBATCHES completed")
}

// parseNZNumber parses an IMAP nz-number: no sign, no leading zero, at most 32 bits (RFC 9051 9).
func parseNZNumber(v string) (int, bool) {
	n, err := strconv.ParseUint(v, 10, 32)
	return int(n), err == nil && n > 0 && n <= math.MaxInt && v[0] != '0'
}
