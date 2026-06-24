// SEARCH criteria matching for IMAP.
package mail

// SearchCriteria is a minimal IMAP SEARCH filter (AND of set fields).
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
}

// MatchSearch returns 1-based sequence numbers matching criteria in msgs order.
func MatchSearch(msgs []Message, c SearchCriteria) []uint32 {
	var out []uint32
	for i, m := range msgs {
		if !matchSearchOne(m, c) {
			continue
		}
		out = append(out, uint32(i+1))
	}
	return out
}

func matchSearchOne(m Message, c SearchCriteria) bool {
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
	if c.All {
		return true
	}
	return c.UIDSet || c.Seen != nil || c.Flagged != nil || c.Answered != nil ||
		c.Deleted != nil || c.Draft != nil || c.Recent != nil
}

// MatchSearchUID returns UIDs matching criteria (for UID SEARCH responses).
func MatchSearchUID(msgs []Message, c SearchCriteria) []uint32 {
	seqs := MatchSearch(msgs, c)
	out := make([]uint32, len(seqs))
	for i, seq := range seqs {
		out[i] = msgs[seq-1].UID
	}
	return out
}
