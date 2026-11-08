// IMAP mailbox subscription state (SUBSCRIBE / UNSUBSCRIBE).
package mail

import (
	"context"
	"errors"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// mailboxSubscribed reports whether folder m appears in LSUB / LIST (SUBSCRIBED).
func mailboxSubscribed(m storage.Mailbox) bool {
	if m.SubSet && !m.Subscribed {
		return false
	}
	return true
}

// RepairImportedSubscriptions resets import-era folders that were stored unsubscribed.
func (ib *Inbox) RepairImportedSubscriptions(ctx context.Context, accountID uint32) error {
	return ib.repairMailboxSubscriptions(ctx, accountID)
}

// repairMailboxSubscriptions clears SubSet on import-era folders stored unsubscribed.
func (ib *Inbox) repairMailboxSubscriptions(ctx context.Context, accountID uint32) error {
	records, err := ib.listMailboxRecords(ctx, accountID)
	if err != nil {
		return err
	}
	return ib.update(ctx, func(t *txn) error {
		for _, r := range records {
			if r.ID <= DraftsMailboxID || !r.SubSet || r.Subscribed {
				continue
			}
			m, err := t.mailbox(accountID, r.ID)
			if errors.Is(err, storage.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			m.SubSet = false
			m.Subscribed = false
			if err := t.putMailbox(accountID, m); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetMailboxSubscribed updates the IMAP subscription flag for an existing folder.
func (ib *Inbox) SetMailboxSubscribed(ctx context.Context, accountID uint32, imapName string, subscribed bool) error {
	mb, err := ib.ResolveMailbox(ctx, accountID, imapName)
	if err != nil {
		return err
	}
	return ib.update(ctx, func(t *txn) error {
		rec, err := t.mailbox(accountID, mb.ID)
		if err != nil {
			return err
		}
		rec.Subscribed = subscribed
		rec.SubSet = true
		return t.putMailbox(accountID, rec)
	})
}
