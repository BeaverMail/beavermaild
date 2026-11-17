// IMAP EXPUNGE and UID EXPUNGE (RFC 4315) for deleted messages.
package imap

import (
	"context"
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
	removed, err := s.expungeMarkedDeleted(ctx, nil, true)
	if err != nil {
		return err
	}
	code, err := s.highestModSeqCode(ctx, removed > 0)
	if err != nil {
		return err
	}
	return s.tagged(tag, "OK "+code+"EXPUNGE completed")
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
	removed, err := s.expungeMarkedDeleted(ctx, uidFilter, allUIDs)
	if err != nil {
		return err
	}
	code, err := s.highestModSeqCode(ctx, removed > 0)
	if err != nil {
		return err
	}
	return s.tagged(tag, "OK "+code+"UID EXPUNGE completed")
}

// expungeMarkedDeleted deletes matching \Deleted messages, emits untagged EXPUNGE lines and returns
// how many it removed. It syncs first, so flags set and expunges done by other sessions count.
func (s *session) expungeMarkedDeleted(ctx context.Context, uidFilter map[uint32]struct{}, allUIDs bool) (int, error) {
	if err := s.pushIdleMailboxChanges(ctx); err != nil {
		return 0, err
	}
	var ids []uint32
	for _, m := range s.messages {
		_, picked := uidFilter[m.UID]
		if m.Meta.Flags&mail.FlagDeleted != 0 && (allUIDs || picked) {
			ids = append(ids, m.StorageID())
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	done, err := s.inbox.ExpungeMessages(ctx, s.principal.AccountID, s.mbox.ID, ids)
	if err != nil {
		return 0, err
	}
	// Messages not expunged changed meanwhile in another session: the next sync reports them.
	gone := make(map[uint32]struct{}, len(done))
	for _, id := range done {
		gone[id] = struct{}{}
	}
	for i := 0; i < len(s.messages); {
		if _, ok := gone[s.messages[i].StorageID()]; !ok {
			i++
			continue
		}
		if err := s.sendExpunge(i+1, s.messages[i].UID); err != nil {
			return 0, err
		}
		s.messages = slices.Delete(s.messages, i, i+1)
	}
	return len(done), nil
}
