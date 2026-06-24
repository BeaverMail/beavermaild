// Message deletion from a mailbox (IMAP EXPUNGE).
package mail

import (
	"context"

	"github.com/BeaverMail/beaver/internal/storage"
)

// DeleteMessage removes email metadata from the store (blob content is retained).
func (ib *Inbox) DeleteMessage(ctx context.Context, accountID, emailID uint32) error {
	batch := storage.NewBatch().WithAccount(accountID)
	suffix := storage.DocumentSuffix(storage.CollectionEmail, emailID, nil)
	if err := batch.Delete(storage.SubspaceMail, suffix); err != nil {
		return err
	}
	return ib.store.Commit(ctx, batch)
}
