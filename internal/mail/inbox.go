// Inbound mail delivery into the KV store and blob filesystem.
package mail

import (
	"context"
	"fmt"
	"log/slog"
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
	log            *slog.Logger
}

// SetLogger sets where storage diagnostics (slow or timed-out write locks) go.
func (ib *Inbox) SetLogger(log *slog.Logger) { ib.log = log }

func (ib *Inbox) logger() *slog.Logger {
	if ib.log == nil {
		return slog.Default()
	}
	return ib.log
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

// storeMessage writes the blob, then stores it as one message (storeMessages).
func (ib *Inbox) storeMessage(ctx context.Context, accountID, mailboxID uint32, raw []byte, flags uint32, receivedAt int64) (uint32, error) {
	if err := ib.checkQuota(ctx, accountID, uint64(len(raw)), 1); err != nil {
		return 0, err
	}
	hash, err := ib.blobs.Put(ctx, raw)
	if err != nil {
		return 0, err
	}
	stored := StoredBlob{Hash: hash, Size: uint32(len(raw)), VSize: wireSize(raw)}
	out, err := ib.storeMessages(ctx, accountID, mailboxID, []AppendMessage{{Blob: stored, Flags: flags, ReceivedAt: receivedAt}})
	if err != nil {
		return 0, err
	}
	return out[0].EmailID, nil
}

// storeMessages writes the message rows, index entries, mailbox counters and quota usage of msgs,
// whose blobs are stored already, in one transaction: all of them or none. On failure the blobs
// stay unreferenced until blob.GC removes them.
func (ib *Inbox) storeMessages(ctx context.Context, accountID, mailboxID uint32, msgs []AppendMessage) ([]Appended, error) {
	out := make([]Appended, len(msgs))
	var bytes int64
	for _, m := range msgs {
		bytes += int64(m.Blob.Size)
	}
	err := ib.update(ctx, accountID, func(t *txn) error {
		mbox, err := t.mailbox(accountID, mailboxID)
		if err != nil {
			return err
		}
		for i, m := range msgs {
			emailID, err := t.nextEmailID(accountID)
			if err != nil {
				return err
			}
			uid, err := t.nextUID(accountID, &mbox)
			if err != nil {
				return err
			}
			meta := storage.EmailMeta{
				Version:    1,
				MailboxID:  mailboxID,
				ReceivedAt: m.ReceivedAt,
				Size:       m.Blob.Size,
				VSize:      m.Blob.VSize,
				Flags:      m.Flags | FlagRecent,
				ModSeq:     nextModSeq(&mbox),
				IMAPUID:    uid,
				BlobHash:   m.Blob.Hash,
			}
			ApplyKeywords(&meta, m.Keywords, nil)
			if err := t.putMeta(accountID, emailID, meta); err != nil {
				return err
			}
			t.indexAdd(accountID, mailboxID, emailID)
			out[i] = Appended{EmailID: emailID, UID: uid}
		}
		if err := t.bumpCount(accountID, &mbox, int32(len(msgs))); err != nil {
			return err
		}
		if err := t.putMailbox(accountID, mbox); err != nil {
			return err
		}
		return t.addQuota(accountID, bytes, int32(len(msgs)))
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
