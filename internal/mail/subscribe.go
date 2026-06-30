// IMAP mailbox subscription state (SUBSCRIBE / UNSUBSCRIBE).
package mail

import (
	"context"

	"github.com/BeaverMail/beaver/internal/storage"
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
	batch := storage.NewBatch().WithAccount(accountID)
	changed := false
	for _, m := range records {
		if m.ID <= DraftsMailboxID || !m.SubSet || m.Subscribed {
			continue
		}
		m.SubSet = false
		m.Subscribed = false
		wire, err := storage.MarshalPersist(nil, 1, m)
		if err != nil {
			return err
		}
		suffix := storage.DocumentSuffix(storage.CollectionMailbox, m.ID, nil)
		if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return ib.store.Commit(ctx, batch)
}

// SetMailboxSubscribed updates the IMAP subscription flag for an existing folder.
func (ib *Inbox) SetMailboxSubscribed(ctx context.Context, accountID uint32, imapName string, subscribed bool) error {
	mb, err := ib.ResolveMailbox(ctx, accountID, imapName)
	if err != nil {
		return err
	}
	rec, err := ib.mailboxRecord(ctx, accountID, mb.ID)
	if err != nil {
		return err
	}
	rec.Subscribed = subscribed
	rec.SubSet = true
	wire, err := storage.MarshalPersist(nil, 1, rec)
	if err != nil {
		return err
	}
	batch := storage.NewBatch().WithAccount(accountID)
	suffix := storage.DocumentSuffix(storage.CollectionMailbox, mb.ID, nil)
	if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
		return err
	}
	return ib.store.Commit(ctx, batch)
}
