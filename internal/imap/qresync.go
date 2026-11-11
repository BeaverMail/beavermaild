// IMAP QRESYNC (RFC 7162 section 3.2): VANISHED responses and SELECT resynchronization.
package imap

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// qresyncParams is the SELECT (QRESYNC (uidvalidity modseq [known-uids] ...)) parameter.
type qresyncParams struct {
	uidValidity uint32
	modSeq      uint64
	knownUIDs   *seqSet // nil: every UID
}

// parseQResyncParams parses the inside of QRESYNC (...); the optional seq-match-data, a
// bandwidth hint for servers that keep expunge history, is ignored.
func parseQResyncParams(inner string) (*qresyncParams, bool) {
	fields := strings.Fields(inner)
	if len(fields) < 2 {
		return nil, false
	}
	uv, err1 := strconv.ParseUint(fields[0], 10, 32)
	ms, err2 := strconv.ParseUint(fields[1], 10, 63)
	if err1 != nil || err2 != nil || uv == 0 || ms == 0 {
		return nil, false
	}
	p := &qresyncParams{uidValidity: uint32(uv), modSeq: ms}
	if len(fields) > 2 && !strings.HasPrefix(fields[2], "(") {
		set, err := parseSeqSet(fields[2])
		if err != nil {
			return nil, false
		}
		p.knownUIDs = &set
	}
	return p, true
}

// sendExpunge reports that the message at seq (1-based) with uid is gone: VANISHED once the
// client enabled QRESYNC, EXPUNGE otherwise (RFC 7162 3.2.10).
func (s *session) sendExpunge(seq int, uid uint32) error {
	if err := s.contextsExpunge(seq, uid); err != nil {
		return err
	}
	if s.qresync {
		return s.untagged("VANISHED " + strconv.FormatUint(uint64(uid), 10))
	}
	return s.untagged(fmt.Sprintf("%d EXPUNGE", seq))
}

// vanishedSet returns, as a UID set, the UIDs of set (nil: all) up to maxUID that no message in
// msgs (sorted by UID) has. Without an expunge history this is what VANISHED (EARLIER) may list
// (RFC 7162 3.2.5.1): UIDs only grow, so every missing UID below UIDNEXT was expunged.
func vanishedSet(set *seqSet, maxUID uint32, msgs []mail.Message) string {
	if maxUID == 0 {
		return ""
	}
	ranges := []seqRange{{1, maxUID}}
	if set != nil {
		ranges = ranges[:0]
		for _, r := range set.ranges {
			lo, hi := cmp.Or(r.lo, maxUID), cmp.Or(r.hi, maxUID) // 0 is "*"
			if lo > hi {
				lo, hi = hi, lo
			}
			if lo <= maxUID {
				ranges = append(ranges, seqRange{lo, min(hi, maxUID)})
			}
		}
		slices.SortFunc(ranges, func(a, b seqRange) int { return cmp.Compare(a.lo, b.lo) })
	}
	var parts []string
	add := func(lo, hi uint32) {
		if lo == hi {
			parts = append(parts, strconv.FormatUint(uint64(lo), 10))
		} else {
			parts = append(parts, fmt.Sprintf("%d:%d", lo, hi))
		}
	}
	next := uint32(1) // first UID not yet covered, so overlapping ranges are reported once
	for _, r := range ranges {
		lo := max(r.lo, next)
		if lo > r.hi {
			continue
		}
		i, _ := slices.BinarySearchFunc(msgs, lo, func(m mail.Message, u uint32) int { return cmp.Compare(m.UID, u) })
		for ; i < len(msgs) && msgs[i].UID <= r.hi; i++ {
			if msgs[i].UID > lo {
				add(lo, msgs[i].UID-1)
			}
			lo = msgs[i].UID + 1
		}
		if lo <= r.hi {
			add(lo, r.hi)
		}
		next = r.hi + 1
	}
	return strings.Join(parts, ",")
}

// qresyncSelect sends what changed since the client's cached state, after a SELECT with QRESYNC:
// the expunged UIDs, then the messages changed after its MODSEQ.
func (s *session) qresyncSelect(p *qresyncParams, uidNext uint32) error {
	if p.uidValidity != s.mbox.UIDValidity {
		return nil // the client's cache is void; it resynchronizes in full
	}
	if v := vanishedSet(p.knownUIDs, max(uidNext, 1)-1, s.messages); v != "" {
		if err := s.untagged("VANISHED (EARLIER) " + v); err != nil {
			return err
		}
	}
	for i, m := range s.messages {
		if max(m.Meta.ModSeq, 1) <= p.modSeq {
			continue
		}
		line := fmt.Sprintf("%d FETCH (UID %d FLAGS %s %s)", i+1, m.UID, mail.FormatMessageFlags(m.Meta), formatModSeq(max(m.Meta.ModSeq, 1)))
		if err := s.untagged(line); err != nil {
			return err
		}
	}
	return nil
}
