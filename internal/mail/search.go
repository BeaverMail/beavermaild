// SEARCH criteria matching for IMAP.
package mail

import (
	"bytes"
	"mime"
	"net/mail"
	"net/textproto"
	"slices"
	"strings"
	"time"
)

// HeaderCriterion is one IMAP SEARCH HEADER field/value pair (ANDed).
type HeaderCriterion struct {
	Field string
	Value string
}

// SearchCriteria is an IMAP SEARCH filter (AND of set fields).
type SearchCriteria struct {
	All      bool
	Seen     *bool
	Flagged  *bool
	Answered *bool
	Deleted  *bool
	Draft    *bool
	Recent   *bool
	UIDs     []SeqRange // UID criterion; nil when unset
	Seqs     []SeqRange // bare sequence-set criterion; nil when unset
	ModSeq   *uint64    // MODSEQ criterion: per-message mod-sequence >= value

	From       string
	To         string
	CC         string
	BCC        string
	Subject    string
	Text       string
	Body       string
	Headers    []HeaderCriterion
	Larger     *uint32    // RFC822 size strictly greater than this
	Smaller    *uint32    // RFC822 size strictly less than this
	Since      *time.Time // inclusive, start of day UTC (ReceivedAt)
	Before     *time.Time // exclusive, start of day UTC (ReceivedAt)
	On         *time.Time // calendar day UTC (ReceivedAt)
	SentSince  *time.Time // Date header, inclusive day in the sender's zone
	SentBefore *time.Time // Date header, exclusive day in the sender's zone
	SentOn     *time.Time // Date header, calendar day in the sender's zone
	Keyword    string     // KEYWORD criterion
	Unkeyword  string     // UNKEYWORD criterion
}

// SeqRange is one IMAP sequence-set range; 0 stands for "*" (the largest value in the mailbox).
type SeqRange struct {
	Lo, Hi uint32
}

// seqRangesContain reports whether n falls in ranges, with "*" resolved to largest.
func seqRangesContain(ranges []SeqRange, n, largest uint32) bool {
	for _, r := range ranges {
		lo, hi := r.Lo, r.Hi
		if lo == 0 {
			lo = largest
		}
		if hi == 0 {
			hi = largest
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		if n >= lo && n <= hi {
			return true
		}
	}
	return false
}

// searchPos locates one message in the mailbox, for sequence-set and UID criteria.
type searchPos struct {
	seq    uint32 // 1-based sequence number
	count  uint32 // messages in the mailbox ("*" for sequence sets)
	maxUID uint32 // largest UID in the mailbox ("*" for UID sets)
}

// newSearchPos returns the position of msgs[0]; advance with seq++.
func newSearchPos(msgs []Message) searchPos {
	p := searchPos{count: uint32(len(msgs))}
	for _, m := range msgs {
		if m.UID > p.maxUID {
			p.maxUID = m.UID
		}
	}
	return p
}

// MatchSearch returns 1-based sequence numbers matching criteria in msgs order.
func MatchSearch(msgs []Message, c SearchCriteria) []uint32 {
	return MatchSearchWithLoader(msgs, c, nil)
}

// MatchSearchWithLoader matches criteria, loading raw message bytes when header fields are set.
func MatchSearchWithLoader(msgs []Message, c SearchCriteria, load RawLoader) []uint32 {
	var out []uint32
	pos := newSearchPos(msgs)
	for i, m := range msgs {
		pos.seq = uint32(i + 1)
		if !matchSearchOne(m, pos, c, load) {
			continue
		}
		out = append(out, pos.seq)
	}
	return out
}

func matchSearchOne(m Message, pos searchPos, c SearchCriteria, load RawLoader) bool {
	if c.UIDs != nil && !seqRangesContain(c.UIDs, m.UID, pos.maxUID) {
		return false
	}
	if c.Seqs != nil && !seqRangesContain(c.Seqs, pos.seq, pos.count) {
		return false
	}
	if c.ModSeq != nil && m.Meta.ModSeq < *c.ModSeq {
		return false
	}
	if c.Seen != nil {
		seen := m.Meta.Flags&FlagSeen != 0
		if seen != *c.Seen {
			return false
		}
	}
	if c.Flagged != nil {
		flagged := m.Meta.Flags&FlagFlagged != 0
		if flagged != *c.Flagged {
			return false
		}
	}
	if c.Answered != nil {
		answered := m.Meta.Flags&FlagAnswered != 0
		if answered != *c.Answered {
			return false
		}
	}
	if c.Deleted != nil {
		deleted := m.Meta.Flags&FlagDeleted != 0
		if deleted != *c.Deleted {
			return false
		}
	}
	if c.Draft != nil {
		draft := m.Meta.Flags&FlagDraft != 0
		if draft != *c.Draft {
			return false
		}
	}
	if c.Recent != nil {
		recent := m.Meta.Flags&FlagRecent != 0
		if recent != *c.Recent {
			return false
		}
	}
	if c.Larger != nil && RFC822Size(m.Meta) <= *c.Larger {
		return false
	}
	if c.Smaller != nil && RFC822Size(m.Meta) >= *c.Smaller {
		return false
	}
	if c.Since != nil || c.Before != nil || c.On != nil {
		if !matchSearchDay(time.Unix(m.Meta.ReceivedAt, 0).UTC(), c.Since, c.Before, c.On) {
			return false
		}
	}
	if c.Keyword != "" && !HasKeyword(m.Meta, c.Keyword) {
		return false
	}
	if c.Unkeyword != "" && HasKeyword(m.Meta, c.Unkeyword) {
		return false
	}
	if needsRawSearch(c) {
		if load == nil {
			return false
		}
		if needsHeaderSearch(c) || c.SentSince != nil || c.SentBefore != nil || c.SentOn != nil {
			hdr, ok := loadHeader(load, m)
			if !ok || needsHeaderSearch(c) && !matchSearchHeaders(hdr, c) {
				return false
			}
			if c.SentSince != nil || c.SentBefore != nil || c.SentOn != nil {
				sent, ok := parseMessageDate(hdr)
				if !ok || !matchSearchDay(sent, c.SentSince, c.SentBefore, c.SentOn) {
					return false
				}
			}
		}
		if c.Text != "" && !openContains(load, m, c.Text, false) {
			return false
		}
		if c.Body != "" && !openContains(load, m, c.Body, true) {
			return false
		}
	}
	if c.All {
		return true
	}
	return searchHasCriterion(c)
}

func searchHasCriterion(c SearchCriteria) bool {
	return c.UIDs != nil || c.Seqs != nil || c.ModSeq != nil || c.Seen != nil || c.Flagged != nil || c.Answered != nil ||
		c.Deleted != nil || c.Draft != nil || c.Recent != nil ||
		c.Keyword != "" || c.Unkeyword != "" ||
		needsRawSearch(c) || c.Larger != nil || c.Smaller != nil ||
		c.Since != nil || c.Before != nil || c.On != nil ||
		c.SentSince != nil || c.SentBefore != nil || c.SentOn != nil
}

func needsRawSearch(c SearchCriteria) bool {
	return c.Text != "" || c.Body != "" || needsHeaderSearch(c) ||
		c.SentSince != nil || c.SentBefore != nil || c.SentOn != nil
}

func needsHeaderSearch(c SearchCriteria) bool {
	return c.From != "" || c.To != "" || c.CC != "" || c.BCC != "" ||
		c.Subject != "" || len(c.Headers) > 0
}

func matchSearchDay(t time.Time, since, before, on *time.Time) bool {
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	if on != nil {
		onDay := time.Date(on.Year(), on.Month(), on.Day(), 0, 0, 0, 0, time.UTC)
		if !day.Equal(onDay) {
			return false
		}
	}
	if since != nil {
		sinceDay := time.Date(since.Year(), since.Month(), since.Day(), 0, 0, 0, 0, time.UTC)
		if day.Before(sinceDay) {
			return false
		}
	}
	if before != nil {
		beforeDay := time.Date(before.Year(), before.Month(), before.Day(), 0, 0, 0, 0, time.UTC)
		if !day.Before(beforeDay) {
			return false
		}
	}
	return true
}

func parseMessageDate(raw []byte) (time.Time, bool) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return time.Time{}, false
	}
	date := strings.TrimSpace(msg.Header.Get("Date"))
	if date == "" {
		return time.Time{}, false
	}
	t, err := mail.ParseDate(date)
	if err != nil {
		return time.Time{}, false
	}
	// Keep the sender's zone: SENT* compare the date as written, ignoring time and zone (RFC 3501).
	return t, true
}

func matchSearchHeaders(raw []byte, c SearchCriteria) bool {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return false
	}
	if c.From != "" && !addressContains(msg.Header.Get("From"), c.From) {
		return false
	}
	if c.To != "" && !addressContains(msg.Header.Get("To"), c.To) {
		return false
	}
	if c.CC != "" && !addressContains(msg.Header.Get("Cc"), c.CC) {
		return false
	}
	if c.BCC != "" && !addressContains(msg.Header.Get("Bcc"), c.BCC) {
		return false
	}
	if c.Subject != "" && !headerContains(msg.Header.Get("Subject"), c.Subject) {
		return false
	}
	for _, h := range c.Headers {
		// HEADER field "" matches messages that have the field, whatever its value (RFC 3501).
		// Every occurrence counts: a repeated field matches if any of its values does.
		values, present := msg.Header[textproto.CanonicalMIMEHeaderKey(h.Field)]
		if !present || !slices.ContainsFunc(values, func(v string) bool { return headerContains(v, h.Value) }) {
			return false
		}
	}
	return true
}

// headerContains matches needle against the header value with RFC 2047 encoded words decoded,
// so a UTF-8 search finds "=?UTF-8?Q?...?=" subjects and names.
func headerContains(haystack, needle string) bool {
	if decoded, err := headerDecoder.DecodeHeader(haystack); err == nil {
		haystack = decoded
	}
	return rawContains([]byte(haystack), needle)
}

// addressContains matches an address criterion against the field as written and without RFC 5322
// comments, so "user@example.org" finds "<user (c)@ (c) example.org>" while a real name kept in
// a comment ("user@example.org (Real Name)") still matches.
func addressContains(value, needle string) bool {
	return headerContains(value, needle) || headerContains(stripAddressComments(value), needle)
}

// stripAddressComments drops parenthesized comments outside quoted strings and the spaces next
// to '@' they leave behind.
func stripAddressComments(s string) string {
	var b strings.Builder
	depth, quoted := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			if depth == 0 {
				b.WriteByte(c)
				b.WriteByte(s[i+1])
			}
			i++
		case c == '"' && depth == 0:
			quoted = !quoted
			b.WriteByte(c)
		case c == '(' && !quoted:
			depth++
		case c == ')' && !quoted && depth > 0:
			depth--
		case depth == 0:
			b.WriteByte(c)
		}
	}
	out := b.String()
	for _, sp := range []string{" @", "@ "} {
		for strings.Contains(out, sp) {
			out = strings.ReplaceAll(out, sp, "@")
		}
	}
	return out
}

// headerDecoder decodes the charsets the stdlib knows (UTF-8, ISO-8859-1, US-ASCII);
// words in other charsets fail to decode and the raw value is searched instead.
var headerDecoder = new(mime.WordDecoder)

// rawContains is case-insensitive substring search on RFC822 bytes or header text.
func rawContains(raw []byte, needle string) bool {
	return bytes.Contains(bytes.ToLower(raw), bytes.ToLower([]byte(needle)))
}

// MatchSearchUID returns UIDs matching criteria (for UID SEARCH responses).
func MatchSearchUID(msgs []Message, c SearchCriteria) []uint32 {
	return MatchSearchUIDWithLoader(msgs, c, nil)
}

// MatchSearchUIDWithLoader returns UIDs with optional raw loader for header criteria.
func MatchSearchUIDWithLoader(msgs []Message, c SearchCriteria, load RawLoader) []uint32 {
	seqs := MatchSearchWithLoader(msgs, c, load)
	out := make([]uint32, len(seqs))
	for i, seq := range seqs {
		out[i] = msgs[seq-1].UID
	}
	return out
}
