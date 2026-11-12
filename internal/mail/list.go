// List and load mailbox messages from the KV store and blob filesystem.
package mail

import (
	"context"
	"errors"
	"os"
	"slices"

	"github.com/BeaverMail/beavermaild/internal/storage"
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

// OpenRaw opens the stored message for streaming (the same bytes LoadRaw returns); the caller closes it.
func (ib *Inbox) OpenRaw(ctx context.Context, meta storage.EmailMeta) (*os.File, error) {
	if !meta.HasBlob() {
		return nil, storage.ErrNotFound
	}
	return ib.blobs.Open(ctx, meta.BlobHash)
}

// SetFlags updates persisted flag bits for one message (set OR clear) and bumps MODSEQ when flags change.
func (ib *Inbox) SetFlags(ctx context.Context, accountID, emailID uint32, set, clear uint32) error {
	_, _, err := ib.SetFlagsIfUnchanged(ctx, accountID, emailID, set, clear, nil, nil, 0)
	return err
}

// ClearRecentFlags clears \Recent on all messages in mailboxID and returns the IDs it cleared.
func (ib *Inbox) ClearRecentFlags(ctx context.Context, accountID, mailboxID uint32) ([]uint32, error) {
	msgs, err := ib.List(ctx, accountID, mailboxID)
	if err != nil {
		return nil, err
	}
	var ids []uint32
	for _, m := range msgs {
		if m.Meta.Flags&FlagRecent != 0 {
			ids = append(ids, m.EmailID)
		}
	}
	return ib.ClearRecentFlagsOf(ctx, accountID, mailboxID, ids)
}

// ClearRecentFlagsOf clears \Recent on the given messages of mailboxID and returns the IDs it
// cleared: the caller is the one session that reports them as recent (RFC 3501 2.3.2).
func (ib *Inbox) ClearRecentFlagsOf(ctx context.Context, accountID, mailboxID uint32, ids []uint32) ([]uint32, error) {
	// Every session that sees a new message tries to claim it at about the same time; only the first
	// can. Neither the check nor the claim queues on the account write lock: CAS picks the winner.
	metas, err := ib.loadEmailMetaBatch(ctx, accountID, ids)
	if err != nil {
		return nil, err
	}
	ids = slices.DeleteFunc(slices.Clone(ids), func(id uint32) bool {
		m, ok := metas[id]
		return !ok || m.Flags&FlagRecent == 0 || m.MailboxID != mailboxID
	})
	if len(ids) == 0 {
		return nil, nil
	}
	var cleared []uint32
	err = ib.updateOptimistic(ctx, func(t *txn) error {
		cleared = cleared[:0]
		for _, id := range ids {
			meta, err := t.meta(accountID, id)
			if errors.Is(err, storage.ErrNotFound) {
				continue // expunged meanwhile
			}
			if err != nil {
				return err
			}
			if meta.Flags&FlagRecent == 0 || meta.MailboxID != mailboxID {
				continue
			}
			cleared = append(cleared, id)
			// No MODSEQ bump: \Recent is per-session state, and sessions that did not claim it never see it.
			meta.Flags &^= FlagRecent
			if err := t.putMeta(accountID, id, meta); err != nil {
				return err
			}
		}
		return nil
	})
	return cleared, err
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
