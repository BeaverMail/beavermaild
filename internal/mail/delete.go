// Message deletion from a mailbox (IMAP EXPUNGE).
package mail

import (
	"context"

	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
)

// DeleteMessage removes email metadata and drops the blob when it is unreferenced.
func (ib *Inbox) DeleteMessage(ctx context.Context, accountID, emailID uint32) error {
	var hash [storage.Blake3DigestLen]byte
	var hasBlob bool
	err := ib.update(ctx, func(t *txn) error {
		meta, err := t.meta(accountID, emailID)
		if err != nil {
			return err
		}
		hash, hasBlob = meta.BlobHash, meta.HasBlob()
		mbox, err := t.mailbox(accountID, meta.MailboxID)
		if err != nil {
			return err
		}
		nextModSeq(&mbox)
		t.del(emailKey(accountID, emailID))
		t.indexRemove(accountID, meta.MailboxID, emailID)
		if err := t.bumpCount(accountID, &mbox, -1); err != nil {
			return err
		}
		if err := t.putMailbox(accountID, mbox); err != nil {
			return err
		}
		return t.addQuota(accountID, -int64(meta.Size), -1)
	})
	if err != nil || !hasBlob {
		return err
	}
	return blob.RemoveIfUnreferenced(ctx, ib.store, ib.blobs, hash)
}
