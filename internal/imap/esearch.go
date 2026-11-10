// ESEARCH (RFC 4731) and ESORT (RFC 5267) result options.
package imap

import (
	"strconv"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// returnOpts are the RETURN options of an extended SEARCH or SORT.
type returnOpts struct{ min, max, all, count bool }

// cutReturnOpts parses a leading "RETURN (opts)". present is false when arg has none; ok is
// false on a malformed or unknown option. An empty list means ALL (RFC 4731 3.1).
func cutReturnOpts(arg string) (o returnOpts, rest string, present, ok bool) {
	arg = strings.TrimLeft(arg, " ")
	if len(arg) < 7 || !strings.EqualFold(arg[:6], "RETURN") || (arg[6] != ' ' && arg[6] != '(') {
		return o, arg, false, true
	}
	inner, rest, found := strings.Cut(strings.TrimLeft(arg[6:], " "), ")")
	if !found || !strings.HasPrefix(inner, "(") {
		return o, "", true, false
	}
	fields := strings.Fields(strings.ToUpper(inner[1:]))
	if len(fields) == 0 {
		o.all = true
	}
	for _, f := range fields {
		switch f {
		case "MIN":
			o.min = true
		case "MAX":
			o.max = true
		case "ALL":
			o.all = true
		case "COUNT":
			o.count = true
		default:
			return o, "", true, false
		}
	}
	return o, rest, true, true
}

// esearchLine builds the ESEARCH response for seqs, the matches in result order (ascending for
// SEARCH, sorted for SORT). MIN and MAX are the first and last result; with MODSEQ in the program
// the mod-sequence covers the returned messages: only MIN/MAX ones unless ALL or COUNT is asked.
func (s *session) esearchLine(tag string, byUID bool, seqs []uint32, o returnOpts, usesModSeq bool) string {
	var b strings.Builder
	b.WriteString("ESEARCH (TAG " + quoteIMAPString(tag) + ")")
	if byUID {
		b.WriteString(" UID")
	}
	nums := s.seqsOrUIDs(seqs, byUID)
	if len(nums) > 0 {
		if o.min {
			b.WriteString(" MIN " + strconv.FormatUint(uint64(nums[0]), 10))
		}
		if o.max {
			b.WriteString(" MAX " + strconv.FormatUint(uint64(nums[len(nums)-1]), 10))
		}
		if o.all {
			b.WriteString(" ALL " + compactRuns(nums))
		}
	}
	if o.count {
		b.WriteString(" COUNT " + strconv.Itoa(len(nums)))
	}
	if usesModSeq && len(seqs) > 0 {
		returned := seqs
		if !o.all && !o.count {
			returned = []uint32{seqs[0], seqs[len(seqs)-1]}
			switch {
			case !o.max:
				returned = returned[:1]
			case !o.min:
				returned = returned[1:]
			}
		}
		b.WriteString(" MODSEQ " + strconv.FormatUint(mail.HighestModSeq(s.messages, returned), 10))
	}
	return b.String()
}

// compactRuns writes nums as a sequence-set in their order, folding runs of consecutive
// increasing numbers into ranges (RFC 5267 3.2: no descending ranges).
func compactRuns(nums []uint32) string {
	var b strings.Builder
	for i := 0; i < len(nums); {
		j := i
		for j+1 < len(nums) && nums[j+1] == nums[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(nums[i]), 10))
		if j > i {
			b.WriteString(":" + strconv.FormatUint(uint64(nums[j]), 10))
		}
		i = j + 1
	}
	return b.String()
}
