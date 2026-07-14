// IMAP STATUS counters for mailboxes.
package mail

import (
	"context"
	"strings"
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
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return MailboxStatus{}, err
	}
	if statusNeedFlagCounts(fields) {
		return ib.statusFromMessages(ctx, accountID, mailboxID, mbox.UIDValidity)
	}
	return ib.statusFromIndex(ctx, accountID, mailboxID, mbox.UIDValidity)
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

func (ib *Inbox) statusFromIndex(ctx context.Context, accountID, mailboxID, uidValidity uint32) (MailboxStatus, error) {
	uids, err := ib.ListMailboxIndexUIDs(ctx, accountID, mailboxID)
	if err != nil {
		return MailboxStatus{}, err
	}
	st := MailboxStatus{
		Messages:    uint32(len(uids)),
		UIDNext:     1,
		UIDValidity: uidValidity,
	}
	if len(uids) > 0 {
		st.UIDNext = uids[len(uids)-1] + 1
	}
	return st, nil
}

func (ib *Inbox) statusFromMessages(ctx context.Context, accountID, mailboxID, uidValidity uint32) (MailboxStatus, error) {
	msgs, err := ib.List(ctx, accountID, mailboxID)
	if err != nil {
		return MailboxStatus{}, err
	}
	var unseen, recent uint32
	var uidNext uint32 = 1
	for _, m := range msgs {
		if m.Meta.Flags&FlagRecent != 0 {
			recent++
		}
		if m.Meta.Flags&FlagSeen == 0 {
			unseen++
		}
		if m.UID >= uidNext {
			uidNext = m.UID + 1
		}
	}
	return MailboxStatus{
		Messages:    uint32(len(msgs)),
		Recent:      recent,
		Unseen:      unseen,
		UIDNext:     uidNext,
		UIDValidity: uidValidity,
	}, nil
}
