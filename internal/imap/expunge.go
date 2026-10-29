// IMAP EXPUNGE and UID EXPUNGE (RFC 4315) for deleted messages.
package imap

import (
	"context"
	"fmt"
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

// expungeMarkedDeleted deletes matching \Deleted messages and emits untagged EXPUNGE lines.
func (s *session) expungeMarkedDeleted(ctx context.Context, uidFilter map[uint32]struct{}, allUIDs bool) error {
	for {
		var found bool
		for i, m := range s.messages {
			if m.Meta.Flags&mail.FlagDeleted == 0 {
				continue
			}
			if !allUIDs {
				if _, ok := uidFilter[m.UID]; !ok {
					continue
				}
			}
			if err := s.inbox.DeleteMessage(ctx, s.principal.AccountID, m.StorageID()); err != nil {
				return err
			}
			if err := s.untagged(fmt.Sprintf("%d EXPUNGE", i+1)); err != nil {
				return err
			}
			s.messages = append(s.messages[:i], s.messages[i+1:]...)
			found = true
			break
		}
		if !found {
			break
		}
	}
	return nil
}
