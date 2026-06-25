// IMAP mailbox subscription state (SUBSCRIBE / UNSUBSCRIBE).
package mail

import (
	"context"

	"github.com/BeaverMail/beaver/internal/storage"
)

// mailboxSubscribed reports whether folder m appears in LSUB.
func mailboxSubscribed(m storage.Mailbox) bool {
	if m.SubSet {
		return m.Subscribed
	}
	return m.ID <= DraftsMailboxID
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
