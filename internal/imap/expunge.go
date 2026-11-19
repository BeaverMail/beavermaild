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
	removed, err := s.expungeMarkedDeleted(ctx, nil)
	if err != nil {
		return err
	}
	code, err := s.highestModSeqCode(ctx, removed > 0)
	if err != nil {
		return err
	}
	return s.tagged(tag, "OK "+code+"EXPUNGE completed")
}

// cmdUIDExpunge removes \Deleted messages whose UID is in the UID set.
func (s *session) cmdUIDExpunge(ctx context.Context, tag, arg string) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	if s.readOnly {
		return s.tagged(tag, "NO mailbox is read-only")
	}
	// The set is required (RFC 4315 4): without it the command would expunge every \Deleted
	// message, which is what UID EXPUNGE exists to avoid.
	set, err := parseSeqSet(strings.TrimSpace(arg))
	if err != nil {
		return s.tagged(tag, "BAD UID EXPUNGE syntax")
	}
	removed, err := s.expungeMarkedDeleted(ctx, &set)
	if err != nil {
		return err
	}
	code, err := s.highestModSeqCode(ctx, removed > 0)
	if err != nil {
		return err
	}
	return s.tagged(tag, "OK "+code+"UID EXPUNGE completed")
}

// expungeMarkedDeleted deletes the \Deleted messages (only those whose UID is in uids, when not
// nil), emits untagged EXPUNGE lines and returns how many it removed. It syncs first, so flags set,
// messages added and expunges done by other sessions count; uids is read after that sync (RFC 4315
// 2.1: every \Deleted message with its UID in the set, also one this session had not seen yet).
func (s *session) expungeMarkedDeleted(ctx context.Context, uids *seqSet) (int, error) {
	if err := s.pushIdleMailboxChanges(ctx); err != nil {
		return 0, err
	}
	picked := make([]bool, len(s.messages))
	if uids != nil {
		for _, idx := range s.resolveIndices(*uids, true) {
			picked[idx] = true
		}
	}
	var ids []uint32
	for i, m := range s.messages {
		if m.Meta.Flags&mail.FlagDeleted != 0 && (uids == nil || picked[i]) {
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
