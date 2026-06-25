// Message deletion from a mailbox (IMAP EXPUNGE).
package mail

import (
	"context"

	"github.com/BeaverMail/beaver/internal/storage"
)

// DeleteMessage removes email metadata from the store (blob content is retained).
func (ib *Inbox) DeleteMessage(ctx context.Context, accountID, emailID uint32) error {
	meta, err := ib.GetMeta(ctx, accountID, emailID)
	if err != nil {
		return err
	}
	batch := storage.NewBatch().WithAccount(accountID)
	suffix := storage.DocumentSuffix(storage.CollectionEmail, emailID, nil)
	if err := batch.Delete(storage.SubspaceMail, suffix); err != nil {
		return err
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
		return err
	}
	return ib.subQuotaUsage(ctx, accountID, uint64(meta.Size), 1)
}
