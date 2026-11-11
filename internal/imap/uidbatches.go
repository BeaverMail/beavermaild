// IMAP UIDBATCHES (draft-ietf-mailmaint-imap-uidbatches): split the selected mailbox into UID
// ranges of a given message count, newest first.
package imap

import (
	"strconv"
	"strings"
)

// uidBatchesMin is the smallest batch size a server must accept.
const uidBatchesMin = 500

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
	first, last := 1, int(^uint(0)>>1)
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

// parseNZNumber parses an IMAP nz-number.
func parseNZNumber(v string) (int, bool) {
	n, err := strconv.Atoi(v)
	return n, err == nil && n > 0 && v[0] != '+' && v[0] != '0'
}
