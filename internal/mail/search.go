// SEARCH criteria matching for IMAP.
package mail

import (
	"bytes"
	"net/mail"
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
	UIDMin   uint32
	UIDMax   uint32
	UIDSet   bool

	From    string
	To      string
	Subject string
	Headers []HeaderCriterion
	Since   *time.Time // inclusive, start of day UTC
	Before  *time.Time // exclusive, start of day UTC
	On      *time.Time // calendar day UTC
}

// RawLoader loads RFC 822 bytes for header SEARCH criteria.
type RawLoader func(Message) ([]byte, error)

// MatchSearch returns 1-based sequence numbers matching criteria in msgs order.
func MatchSearch(msgs []Message, c SearchCriteria) []uint32 {
	return MatchSearchWithLoader(msgs, c, nil)
}

// MatchSearchWithLoader matches criteria, loading raw message bytes when header fields are set.
func MatchSearchWithLoader(msgs []Message, c SearchCriteria, load RawLoader) []uint32 {
	var out []uint32
	for i, m := range msgs {
		if !matchSearchOne(m, c, load) {
			continue
		}
		out = append(out, uint32(i+1))
	}
	return out
}

func matchSearchOne(m Message, c SearchCriteria, load RawLoader) bool {
	if c.UIDSet && (m.UID < c.UIDMin || m.UID > c.UIDMax) {
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
	if c.Since != nil || c.Before != nil || c.On != nil {
		if !matchSearchDate(m.Meta.ReceivedAt, c) {
			return false
		}
	}
	if needsHeaderSearch(c) {
		if load == nil {
			return false
		}
		raw, err := load(m)
		if err != nil || !matchSearchHeaders(raw, c) {
			return false
		}
	}
	if c.All {
		return true
	}
	return c.UIDSet || c.Seen != nil || c.Flagged != nil || c.Answered != nil ||
		c.Deleted != nil || c.Draft != nil || c.Recent != nil ||
		needsHeaderSearch(c) || c.Since != nil || c.Before != nil || c.On != nil
}

func needsHeaderSearch(c SearchCriteria) bool {
	return c.From != "" || c.To != "" || c.Subject != "" || len(c.Headers) > 0
}

func matchSearchDate(receivedAt int64, c SearchCriteria) bool {
	t := time.Unix(receivedAt, 0).UTC()
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	if c.On != nil {
		on := time.Date(c.On.Year(), c.On.Month(), c.On.Day(), 0, 0, 0, 0, time.UTC)
		if !day.Equal(on) {
			return false
		}
	}
	if c.Since != nil {
		since := time.Date(c.Since.Year(), c.Since.Month(), c.Since.Day(), 0, 0, 0, 0, time.UTC)
		if day.Before(since) {
			return false
		}
	}
	if c.Before != nil {
		before := time.Date(c.Before.Year(), c.Before.Month(), c.Before.Day(), 0, 0, 0, 0, time.UTC)
		if !day.Before(before) {
			return false
		}
	}
	return true
}

func matchSearchHeaders(raw []byte, c SearchCriteria) bool {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return false
	}
	if c.From != "" && !headerContains(msg.Header.Get("From"), c.From) {
		return false
	}
	if c.To != "" && !headerContains(msg.Header.Get("To"), c.To) {
		return false
	}
	if c.Subject != "" && !headerContains(msg.Header.Get("Subject"), c.Subject) {
		return false
	}
	for _, h := range c.Headers {
		if !headerContains(msg.Header.Get(h.Field), h.Value) {
			return false
		}
	}
	return true
}

func headerContains(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
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
