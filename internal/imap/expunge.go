// IMAP EXPUNGE and UID EXPUNGE (RFC 4315) for deleted messages.
package imap

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// cmdExpunge permanently removes all messages marked \Deleted in the selected mailbox.
func (s *session) cmdExpunge(ctx context.Context, tag string) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	if s.readOnly {
		return s.tagged(tag, "NO mailbox is read-only")
	}
	if err := s.expungeMarkedDeleted(ctx, nil, true); err != nil {
		return err
	}
	return s.tagged(tag, "OK EXPUNGE completed")
}

// cmdUIDExpunge removes \Deleted messages whose UID is in the optional UID set.
func (s *session) cmdUIDExpunge(ctx context.Context, tag, arg string) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	if s.readOnly {
		return s.tagged(tag, "NO mailbox is read-only")
	}
	arg = strings.TrimSpace(arg)
	allUIDs := arg == ""
	uidFilter := make(map[uint32]struct{})
	if !allUIDs {
		set, err := parseSeqSet(arg)
		if err != nil {
			return s.tagged(tag, "BAD UID EXPUNGE syntax")
		}
		for _, idx := range s.resolveIndices(set, true) {
			if idx < 0 || idx >= len(s.messages) {
				continue
			}
			uidFilter[s.messages[idx].UID] = struct{}{}
		}
	}
	if err := s.expungeMarkedDeleted(ctx, uidFilter, allUIDs); err != nil {
		return err
	}
	return s.tagged(tag, "OK UID EXPUNGE completed")
}

// expungeMarkedDeleted deletes matching \Deleted messages and emits untagged EXPUNGE lines. It syncs
// first, so flags set and expunges done by other sessions count.
func (s *session) expungeMarkedDeleted(ctx context.Context, uidFilter map[uint32]struct{}, allUIDs bool) error {
	if err := s.pushIdleMailboxChanges(ctx); err != nil {
		return err
	}
	for i := 0; i < len(s.messages); {
		m := s.messages[i]
		_, picked := uidFilter[m.UID]
		if m.Meta.Flags&mail.FlagDeleted == 0 || !(allUIDs || picked) {
			i++
			continue
		}
		expunged, err := s.inbox.ExpungeMessage(ctx, s.principal.AccountID, s.mbox.ID, m.StorageID())
		if err != nil {
			return err
		}
		if !expunged {
			i++ // changed meanwhile by another session: the next sync reports it
			continue
		}
		if err := s.untagged(fmt.Sprintf("%d EXPUNGE", i+1)); err != nil {
			return err
		}
		s.messages = slices.Delete(s.messages, i, i+1)
	}
	return nil
}
