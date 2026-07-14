// IMAP STATUS counters for mailboxes.
package mail

import (
	"context"
	"strings"

	"github.com/BeaverMail/beaver/internal/storage"
)

// MailboxStatus holds IMAP STATUS counters for one folder.
type MailboxStatus struct {
	Messages    uint32
	Recent      uint32
	Unseen      uint32
	UIDNext     uint32
	UIDValidity uint32
}

// Status returns requested STATUS fields for mailboxID.
// When fields omit UNSEEN and RECENT, only the mailbox index is scanned (no meta load).
func (ib *Inbox) Status(ctx context.Context, accountID, mailboxID uint32, fields []string) (MailboxStatus, error) {
	if err := ib.ensureIMAPUIDBackfill(ctx, accountID, mailboxID); err != nil {
		return MailboxStatus{}, err
	}
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return MailboxStatus{}, err
	}
	if statusNeedFlagCounts(fields) {
		return ib.statusFromMessages(ctx, accountID, mailboxID, mbox)
	}
	return ib.statusFromIndex(ctx, accountID, mailboxID, mbox)
}

func statusNeedFlagCounts(fields []string) bool {
	for _, f := range fields {
		switch strings.ToUpper(strings.TrimSpace(f)) {
		case "UNSEEN", "RECENT":
			return true
		}
	}
	return false
}

func (ib *Inbox) statusFromIndex(ctx context.Context, accountID, mailboxID uint32, mbox storage.Mailbox) (MailboxStatus, error) {
	emailIDs, err := ib.ListMailboxIndexEmailIDs(ctx, accountID, mailboxID)
	if err != nil {
		return MailboxStatus{}, err
	}
	uidNext := mbox.UIDNext
	if uidNext == 0 {
		uidNext = 1
	}
	return MailboxStatus{
		Messages:    uint32(len(emailIDs)),
		UIDNext:     uidNext,
		UIDValidity: mbox.UIDValidity,
	}, nil
}

func (ib *Inbox) statusFromMessages(ctx context.Context, accountID, mailboxID uint32, mbox storage.Mailbox) (MailboxStatus, error) {
	msgs, err := ib.List(ctx, accountID, mailboxID)
	if err != nil {
		return MailboxStatus{}, err
	}
	var unseen, recent uint32
	for _, m := range msgs {
		if m.Meta.Flags&FlagRecent != 0 {
			recent++
		}
		if m.Meta.Flags&FlagSeen == 0 {
			unseen++
		}
	}
	uidNext := mbox.UIDNext
	if uidNext == 0 {
		uidNext = 1
	}
	return MailboxStatus{
		Messages:    uint32(len(msgs)),
		Recent:      recent,
		Unseen:      unseen,
		UIDNext:     uidNext,
		UIDValidity: mbox.UIDValidity,
	}, nil
}
