// IDLE unsolicited mailbox updates (RFC 2177): EXISTS, FETCH, EXPUNGE, RECENT.
package imap

import (
	"context"
	"fmt"
	"slices"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
)

// pushIdleMailboxChanges compares storage to the session cache and emits untagged updates. IDLE
// calls it on each change, and every other command before its tagged reply (see tagged).
func (s *session) pushIdleMailboxChanges(ctx context.Context) error {
	highest, err := s.inbox.HighestModSeq(ctx, s.principal.AccountID, s.mbox.ID)
	if err != nil {
		return err
	}
	if highest == s.idleWatchModSeq {
		return nil
	}

	// Always a full reload: reusing cached metadata would drop flag changes made together with
	// new or expunged messages.
	fresh, err := s.inbox.List(ctx, s.principal.AccountID, s.mbox.ID)
	if err != nil {
		return err
	}
	// The first SELECT session to see a new message takes its \Recent; EXAMINE never does.
	if err := s.claimRecent(ctx, s.mbox.ID, fresh); err != nil {
		return err
	}
	s.keepRecent(fresh)
	if err := s.announceKeywords(fresh); err != nil {
		return err
	}
	return s.applyIdleMailboxDiff(fresh, highest)
}

// applyIdleMailboxDiff emits IDLE updates and refreshes the session snapshot.
func (s *session) applyIdleMailboxDiff(fresh []mail.Message, highestMod uint64) error {
	oldRecent := countRecentFlags(s.messages)
	freshByUID := make(map[uint32]mail.Message, len(fresh))
	for _, m := range fresh {
		freshByUID[m.UID] = m
	}

	for i := 0; i < len(s.messages); {
		if _, ok := freshByUID[s.messages[i].UID]; !ok {
			if err := s.sendExpunge(i+1, s.messages[i].UID); err != nil {
				return err
			}
			s.messages = append(s.messages[:i], s.messages[i+1:]...)
			continue
		}
		i++
	}

	for i := 0; i < len(s.messages) && i < len(fresh); i++ {
		if s.messages[i].UID != fresh[i].UID {
			break
		}
		if !messageMetaEqual(s.messages[i].Meta, fresh[i].Meta) {
			if err := s.emitIdleFetch(i+1, fresh[i]); err != nil {
				return err
			}
		}
	}

	if len(fresh) > len(s.messages) {
		if err := s.untagged(fmt.Sprintf("%d EXISTS", len(fresh))); err != nil {
			return err
		}
	}

	newRecent := countRecentFlags(fresh)
	if newRecent != oldRecent {
		if err := s.untagged(fmt.Sprintf("%d RECENT", newRecent)); err != nil {
			return err
		}
	}

	s.messages = fresh
	s.idleWatchModSeq = highestMod
	return nil
}

// emitIdleFetch sends an unsolicited FLAGS (and optional MODSEQ) FETCH during IDLE.
func (s *session) emitIdleFetch(seq int, msg mail.Message) error {
	line := fmt.Sprintf("%d FETCH (FLAGS %s", seq, mail.FormatMessageFlags(msg.Meta))
	if s.condstore { // RFC 7162 3.2.4: UID and MODSEQ once CONDSTORE is enabled
		line = fmt.Sprintf("%d FETCH (UID %d FLAGS %s", seq, msg.UID, mail.FormatMessageFlags(msg.Meta))
		modSeq := msg.Meta.ModSeq
		if modSeq == 0 {
			modSeq = 1
		}
		line += " " + formatModSeq(modSeq)
	}
	line += ")"
	return s.untagged(line)
}

func countRecentFlags(msgs []mail.Message) int {
	var n int
	for _, m := range msgs {
		if m.Meta.Flags&mail.FlagRecent != 0 {
			n++
		}
	}
	return n
}

func messageMetaEqual(a, b storage.EmailMeta) bool {
	return a.Flags == b.Flags && a.ModSeq == b.ModSeq && slices.Equal(a.Keywords, b.Keywords)
}
