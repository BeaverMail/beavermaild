// IDLE unsolicited mailbox updates (RFC 2177): EXISTS, FETCH, EXPUNGE, RECENT.
package imap

import (
	"context"
	"fmt"
	"slices"

	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage"
)

// pushIdleMailboxChanges compares storage to the session cache and emits untagged updates.
func (s *session) pushIdleMailboxChanges(ctx context.Context) error {
	fresh, err := s.inbox.List(ctx, s.principal.AccountID, s.mbox.ID)
	if err != nil {
		return err
	}
	oldRecent := countRecentFlags(s.messages)
	freshByUID := make(map[uint32]mail.Message, len(fresh))
	for _, m := range fresh {
		freshByUID[m.UID] = m
	}

	for i := 0; i < len(s.messages); {
		if _, ok := freshByUID[s.messages[i].UID]; !ok {
			if err := s.untagged(fmt.Sprintf("%d EXPUNGE", i+1)); err != nil {
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
	return nil
}

// emitIdleFetch sends an unsolicited FLAGS (and optional MODSEQ) FETCH during IDLE.
func (s *session) emitIdleFetch(seq int, msg mail.Message) error {
	line := fmt.Sprintf("%d FETCH (FLAGS %s", seq, mail.FormatMessageFlags(msg.Meta))
	if s.condstore {
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
