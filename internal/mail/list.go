// List and load mailbox messages from the KV store and blob filesystem.
package mail

import (
	"context"
	"errors"

	"github.com/BeaverMail/beaver/internal/storage"
)

// Message is one email in a mailbox. UID is the IMAP UID; EmailID is the storage document id.
type Message struct {
	EmailID uint32
	UID     uint32
	Meta    storage.EmailMeta
}

// StorageID returns the email document id (EmailID, or UID when unset in tests).
func (m Message) StorageID() uint32 {
	if m.EmailID != 0 {
		return m.EmailID
	}
	return m.UID
}

// List returns messages in mailboxID for accountID, sorted by IMAP UID ascending.
func (ib *Inbox) List(ctx context.Context, accountID, mailboxID uint32) ([]Message, error) {
	if _, err := ib.mailboxRecord(ctx, accountID, mailboxID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if err := ib.ensureIMAPUIDBackfill(ctx, accountID, mailboxID); err != nil {
		return nil, err
	}
	ready, err := ib.mailboxIndexReady(ctx, accountID, mailboxID)
	if err != nil {
		return nil, err
	}
	if !ready {
		if err := ib.backfillMailboxIndex(ctx, accountID, mailboxID); err != nil {
			return nil, err
		}
	}
	return ib.listFromMailboxIndex(ctx, accountID, mailboxID)
}

// LoadRaw returns the RFC 5322 bytes for meta (blob hash required).
func (ib *Inbox) LoadRaw(ctx context.Context, meta storage.EmailMeta) ([]byte, error) {
	if !meta.HasBlob() {
		return nil, storage.ErrNotFound
	}
	return ib.blobs.Get(ctx, meta.BlobHash)
}

// SetFlags updates persisted flag bits for one message (set OR clear) and bumps MODSEQ when flags change.
func (ib *Inbox) SetFlags(ctx context.Context, accountID, emailID uint32, set, clear uint32) error {
	_, _, err := ib.SetFlagsIfUnchanged(ctx, accountID, emailID, set, clear, nil, nil, 0)
	return err
}

// ClearRecentFlags clears \Recent on all messages in mailboxID and returns how many were recent.
func (ib *Inbox) ClearRecentFlags(ctx context.Context, accountID, mailboxID uint32) (int, error) {
	msgs, err := ib.List(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}
	var recent int
	batch := storage.NewBatch().WithAccount(accountID)
	for _, m := range msgs {
		if m.Meta.Flags&FlagRecent == 0 {
			continue
		}
		recent++
		meta := m.Meta
		meta.Flags &^= FlagRecent
		modSeq, err := ib.allocateModSeq(ctx, accountID, mailboxID)
		if err != nil {
			return 0, err
		}
		meta.ModSeq = modSeq
		wire, err := storage.MarshalPersist(nil, 1, meta)
		if err != nil {
			return 0, err
		}
		suffix := storage.DocumentSuffix(storage.CollectionEmail, m.EmailID, nil)
		if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
			return 0, err
		}
	}
	if recent == 0 {
		return 0, nil
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
		return 0, err
	}
	return recent, nil
}

// GetMeta loads EmailMeta for accountID and emailID.
func (ib *Inbox) GetMeta(ctx context.Context, accountID, emailID uint32) (storage.EmailMeta, error) {
	key := storage.AppendKey(nil, storage.SubspaceMail, accountID, emailID, byte(storage.CollectionEmail), nil)
	wire, err := ib.store.Get(ctx, key)
	if err != nil {
		return storage.EmailMeta{}, err
	}
	var meta storage.EmailMeta
	if err := storage.UnmarshalPersist(wire, &meta); err != nil {
		return storage.EmailMeta{}, err
	}
	return meta, nil
}
