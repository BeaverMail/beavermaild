// Message deletion from a mailbox (IMAP EXPUNGE).
package mail

import (
	"context"

	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
)

// DeleteMessage removes email metadata and drops the blob when it is unreferenced.
func (ib *Inbox) DeleteMessage(ctx context.Context, accountID, emailID uint32) error {
	meta, err := ib.GetMeta(ctx, accountID, emailID)
	if err != nil {
		return err
	}
	blobHash := meta.BlobHash
	hasBlob := meta.HasBlob()
	batch := storage.NewBatch().WithAccount(accountID)
	suffix := storage.DocumentSuffix(storage.CollectionEmail, emailID, nil)
	if err := batch.Delete(storage.SubspaceMail, suffix); err != nil {
		return err
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
		return err
	}
	if err := ib.subQuotaUsage(ctx, accountID, uint64(meta.Size), 1); err != nil {
		return err
	}
	if hasBlob {
		return blob.RemoveIfUnreferenced(ctx, ib.store, ib.blobs, blobHash)
	}
	return nil
}
