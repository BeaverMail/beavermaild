// Message deletion from a mailbox (IMAP EXPUNGE).
package mail

import (
	"context"
	"errors"

	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
)

// DeleteMessage removes email metadata and drops the blob when it is unreferenced.
func (ib *Inbox) DeleteMessage(ctx context.Context, accountID, emailID uint32) error {
	_, err := ib.deleteMessage(ctx, accountID, emailID, nil)
	return err
}

// ExpungeMessage deletes emailID only if it is still in mailboxID and flagged \Deleted, as
// checked in the same transaction: another session may have moved it or cleared the flag since
// the caller looked. expunged is false when the message stays (or is already gone).
func (ib *Inbox) ExpungeMessage(ctx context.Context, accountID, mailboxID, emailID uint32) (expunged bool, err error) {
	expunged, err = ib.deleteMessage(ctx, accountID, emailID, func(meta storage.EmailMeta) bool {
		return meta.MailboxID == mailboxID && meta.Flags&FlagDeleted != 0
	})
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	return expunged, err
}

// deleteMessage deletes emailID when ok (nil: always) accepts its current metadata.
func (ib *Inbox) deleteMessage(ctx context.Context, accountID, emailID uint32, ok func(storage.EmailMeta) bool) (bool, error) {
	var hash [storage.Blake3DigestLen]byte
	var hasBlob, deleted bool
	err := ib.update(ctx, accountID, func(t *txn) error {
		meta, err := t.meta(accountID, emailID)
		if err != nil {
			return err
		}
		if deleted = ok == nil || ok(meta); !deleted {
			return nil
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
	if err != nil || !deleted || !hasBlob {
		return deleted && err == nil, err
	}
	return true, blob.RemoveIfUnreferenced(ctx, ib.store, ib.blobs, hash)
}
