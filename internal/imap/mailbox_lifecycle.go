// IMAP CLOSE, UNSELECT, and CHECK commands.
package imap

import (
	"context"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// cmdClose expunges deleted messages and returns to the authenticated state.
func (s *session) cmdClose(ctx context.Context, tag string) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	// A read-only mailbox (EXAMINE) is closed without expunging (RFC 3501 CLOSE).
	if !s.readOnly {
		if err := s.purgeDeleted(ctx); err != nil {
			return err
		}
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

// purgeDeleted permanently removes the mailbox's \Deleted messages without EXPUNGE untagged lines.
// It reads the flags from storage: another session may have set \Deleted since the last sync.
func (s *session) purgeDeleted(ctx context.Context) error {
	msgs, err := s.inbox.List(ctx, s.principal.AccountID, s.mbox.ID)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Meta.Flags&mail.FlagDeleted == 0 {
			continue
		}
		if _, err := s.inbox.ExpungeMessage(ctx, s.principal.AccountID, s.mbox.ID, m.StorageID()); err != nil {
			return err
		}
	}
	s.messages = nil
	return nil
}
