// Inbound mail delivery into the KV store and blob filesystem.
package mail

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
)

const InboxMailboxID uint32 = 1

// Inbox stores received messages for an account.
type Inbox struct {
	store storage.Store
	blobs *blob.FS
}

// NewInbox returns a delivery helper over store and blobs.
func NewInbox(store storage.Store, blobs *blob.FS) *Inbox {
	return &Inbox{store: store, blobs: blobs}
}

// Deliver saves raw message bytes to INBOX and returns the new email document id.
func (ib *Inbox) Deliver(ctx context.Context, accountID uint32, raw []byte) (uint32, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("mail: empty message")
	}

	hash, err := ib.blobs.Put(ctx, raw)
	if err != nil {
		return 0, err
	}

	emailID, err := ib.nextEmailID(ctx, accountID)
	if err != nil {
		return 0, err
	}

	meta := storage.EmailMeta{
		Version:    1,
		MailboxID:  InboxMailboxID,
		ReceivedAt: time.Now().Unix(),
		Size:       uint32(len(raw)),
		BlobHash:   hash,
	}
	wire, err := storage.MarshalPersist(nil, 1, meta)
	if err != nil {
		return 0, err
	}

	batch := storage.NewBatch().WithAccount(accountID)
	suffix := storage.DocumentSuffix(storage.CollectionEmail, emailID, nil)
	if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
		return 0, err
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
		return 0, err
	}
	return emailID, nil
}

func (ib *Inbox) nextEmailID(ctx context.Context, accountID uint32) (uint32, error) {
	key := storage.AppendKey(nil, storage.SubspaceLookup, 0, 0, 0,
		[]byte(fmt.Sprintf("meta/email/%d", accountID)))
	wire, err := ib.store.Get(ctx, key)
	var next uint32 = 1
	if err == nil {
		if err := storage.UnmarshalPersist(wire, &next); err != nil {
			return 0, err
		}
		next++
	} else if !errors.Is(err, storage.ErrNotFound) {
		return 0, err
	}

	encoded, err := storage.MarshalPersist(nil, 1, next)
	if err != nil {
		return 0, err
	}
	batch := storage.NewBatch().WithAccount(0)
	suffix := storage.BatchSuffix(0, 0, []byte(fmt.Sprintf("meta/email/%d", accountID)))
	if err := batch.Set(storage.SubspaceLookup, suffix, encoded); err != nil {
		return 0, err
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
		return 0, err
	}
	return next, nil
}
