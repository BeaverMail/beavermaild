// IMAP CLOSE, UNSELECT, and CHECK commands.
package imap

import (
	"context"

	"github.com/BeaverMail/beaver/internal/mail"
)

// cmdClose expunges deleted messages and returns to the authenticated state.
func (s *session) cmdClose(ctx context.Context, tag string) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	if s.readOnly {
		return s.tagged(tag, "NO mailbox is read-only")
	}
	if err := s.purgeDeleted(ctx); err != nil {
		return err
	}
	s.unselect()
	return s.tagged(tag, "OK CLOSE completed")
}

// cmdUnselect closes the selected mailbox without expunging (RFC 3691).
func (s *session) cmdUnselect(tag string) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	s.unselect()
	return s.tagged(tag, "OK UNSELECT completed")
}

// cmdCheck is a polling hint; ponytail: no mailbox scan beyond session state.
func (s *session) cmdCheck(tag string) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	return s.tagged(tag, "OK CHECK completed")
}

func (s *session) unselect() {
	s.selected = false
	s.readOnly = false
	s.messages = nil
	s.idleWatchModSeq = 0
	s.mbox = mail.Mailbox{}
}

// purgeDeleted permanently removes \Deleted messages without EXPUNGE untagged lines.
func (s *session) purgeDeleted(ctx context.Context) error {
	for i := 0; i < len(s.messages); {
		m := s.messages[i]
		if m.Meta.Flags&mail.FlagDeleted == 0 {
			i++
			continue
		}
		if err := s.inbox.DeleteMessage(ctx, s.principal.AccountID, m.UID); err != nil {
			return err
		}
		s.messages = append(s.messages[:i], s.messages[i+1:]...)
	}
	return nil
}
