// Inbound mail delivery into the KV store and blob filesystem.
package mail

import (
	"context"
	"fmt"
	"time"

	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
)

// Inbox stores received messages for an account.
type Inbox struct {
	store          storage.Store
	blobs          *blob.FS
	quotaDefault   QuotaDefaults
	accountQuotaFn AccountQuotaDefaultsFunc
	tenantCapFn    TenantStorageCapFunc
}

// NewInbox returns a delivery helper over store and blobs.
func NewInbox(store storage.Store, blobs *blob.FS) *Inbox {
	return &Inbox{store: store, blobs: blobs}
}

// Blobs returns the content-addressed blob store used by this inbox.
func (ib *Inbox) Blobs() *blob.FS {
	return ib.blobs
}

// Deliver saves raw message bytes to INBOX and returns the new email document id.
func (ib *Inbox) Deliver(ctx context.Context, accountID uint32, raw []byte) (uint32, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("mail: empty message")
	}
	return ib.storeMessage(ctx, accountID, InboxMailboxID, raw, 0, time.Now().Unix())
}

// storeMessage writes the blob, then the message row, index entry, mailbox counters and
// quota usage in one transaction.
func (ib *Inbox) storeMessage(ctx context.Context, accountID, mailboxID uint32, raw []byte, flags uint32, receivedAt int64) (uint32, error) {
	if err := ib.checkQuota(ctx, accountID, uint64(len(raw)), 1); err != nil {
		return 0, err
	}
	hash, err := ib.blobs.Put(ctx, raw)
	if err != nil {
		return 0, err
	}
	var emailID uint32
	err = ib.update(ctx, func(t *txn) error {
		mbox, err := t.mailbox(accountID, mailboxID)
		if err != nil {
			return err
		}
		if emailID, err = t.nextEmailID(accountID); err != nil {
			return err
		}
		uid, err := t.nextUID(accountID, &mbox)
		if err != nil {
			return err
		}
		meta := storage.EmailMeta{
			Version:    1,
			MailboxID:  mailboxID,
			ReceivedAt: receivedAt,
			Size:       uint32(len(raw)),
			Flags:      flags | FlagRecent,
			ModSeq:     nextModSeq(&mbox),
			IMAPUID:    uid,
			BlobHash:   hash,
		}
		if err := t.putMeta(accountID, emailID, meta); err != nil {
			return err
		}
		t.indexAdd(accountID, mailboxID, emailID)
		if err := t.bumpCount(accountID, &mbox, 1); err != nil {
			return err
		}
		if err := t.putMailbox(accountID, mbox); err != nil {
			return err
		}
		return t.addQuota(accountID, int64(len(raw)), 1)
	})
	if err != nil {
		return 0, err
	}
	return emailID, nil
}
