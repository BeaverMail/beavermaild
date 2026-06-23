// IMAP sequence set parsing (RFC 3501 subset).
package imap

import (
	"fmt"
	"strconv"
	"strings"
)

type seqRange struct {
	lo uint32
	hi uint32
}

type seqSet struct {
	ranges []seqRange
}

// parseSeqSet parses "1", "1:3", "2,4", "1:*", "*".
func parseSeqSet(s string) (seqSet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return seqSet{}, fmt.Errorf("imap: empty sequence set")
	}
	var out seqSet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return seqSet{}, fmt.Errorf("imap: empty sequence set part")
		}
		if strings.Contains(part, ":") {
			i := strings.IndexByte(part, ':')
			lo, err := parseSeqToken(strings.TrimSpace(part[:i]))
			if err != nil {
				return seqSet{}, err
			}
			hi, err := parseSeqToken(strings.TrimSpace(part[i+1:]))
			if err != nil {
				return seqSet{}, err
			}
			if lo == 0 || hi == 0 {
				out.ranges = append(out.ranges, seqRange{lo: lo, hi: hi})
			} else if lo > hi {
				return seqSet{}, fmt.Errorf("imap: invalid sequence range")
			} else {
				out.ranges = append(out.ranges, seqRange{lo: lo, hi: hi})
			}
			continue
		}
		n, err := parseSeqToken(part)
		if err != nil {
			return seqSet{}, err
		}
		if n == 0 {
			out.ranges = append(out.ranges, seqRange{})
		} else {
			out.ranges = append(out.ranges, seqRange{lo: n, hi: n})
		}
	}
	return out, nil
}

func parseSeqToken(tok string) (uint32, error) {
	if tok == "*" {
		return 0, nil
	}
	n, err := strconv.ParseUint(tok, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("imap: invalid sequence number %q", tok)
	}
	return uint32(n), nil
}

// expandSeq returns 1-based sequence numbers in ascending order without duplicates.
func (ss seqSet) expandSeq(count uint32) []uint32 {
	if count == 0 {
		return nil
	}
	seen := make(map[uint32]struct{})
	var out []uint32
	for _, r := range ss.ranges {
		lo, hi := r.lo, r.hi
		if lo == 0 {
			lo = count
		}
		if hi == 0 {
			hi = count
		}
		if lo == 0 || hi == 0 {
			continue
		}
		if lo > count {
			continue
		}
		if hi > count {
			hi = count
		}
		for n := lo; n <= hi; n++ {
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	return out
}

// expandUID maps UID sequence sets to message indices (0-based) in msgs.
func (ss seqSet) expandUID(msgs []messageRef) []int {
	if len(msgs) == 0 {
		return nil
	}
	maxUID := msgs[len(msgs)-1].uid
	seen := make(map[int]struct{})
	var out []int
	for _, r := range ss.ranges {
		lo, hi := r.lo, r.hi
		if lo == 0 {
			lo = maxUID
		}
		if hi == 0 {
			hi = maxUID
		}
		if lo == 0 || hi == 0 {
			continue
		}
		if lo > hi {
			continue
		}
		for i, m := range msgs {
			if m.uid < lo || m.uid > hi {
				continue
			}
			if _, ok := seen[i]; ok {
				continue
			}
			seen[i] = struct{}{}
			out = append(out, i)
		}
	}
	return out
}

type messageRef struct {
	uid uint32
}
