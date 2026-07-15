// Denormalized per-mailbox message counts for O(1) empty checks and STATUS.
package mail

import (
	"context"

	"github.com/BeaverMail/beaver/internal/storage"
)

// bumpMailboxMessageCount adjusts Mailbox.MessageCount after the index is already committed.
func (ib *Inbox) bumpMailboxMessageCount(ctx context.Context, accountID, mailboxID uint32, delta int32) error {
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return err
	}
	if mbox.MessageCount == 0 {
		n, err := ib.indexMessageCount(ctx, accountID, mailboxID)
		if err != nil {
			return err
		}
		mbox.MessageCount = n
	} else if delta > 0 {
		mbox.MessageCount += uint32(delta)
	} else if d := uint32(-delta); d > 0 {
		if mbox.MessageCount >= d {
			mbox.MessageCount -= d
		} else {
			mbox.MessageCount = 0
		}
	}
	return ib.saveMailboxRecord(ctx, accountID, mbox)
}

// setMailboxMessageCount stores an exact count (index backfill).
func (ib *Inbox) setMailboxMessageCount(ctx context.Context, accountID, mailboxID uint32, count uint32) error {
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return err
	}
	mbox.MessageCount = count
	return ib.saveMailboxRecord(ctx, accountID, mbox)
}

// mailboxMessageCount returns the stored count, syncing once from the index when still zero.
func (ib *Inbox) mailboxMessageCount(ctx context.Context, accountID, mailboxID uint32) (uint32, error) {
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}
	if mbox.MessageCount > 0 {
		return mbox.MessageCount, nil
	}
	n, err := ib.indexMessageCount(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		mbox.MessageCount = n
		_ = ib.saveMailboxRecord(ctx, accountID, mbox)
	}
	return n, nil
}

func (ib *Inbox) indexMessageCount(ctx context.Context, accountID, mailboxID uint32) (uint32, error) {
	ids, err := ib.ListMailboxIndexEmailIDs(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}
	return uint32(len(ids)), nil
}

func (ib *Inbox) saveMailboxRecord(ctx context.Context, accountID uint32, mbox storage.Mailbox) error {
	wire, err := storage.MarshalPersist(nil, 1, mbox)
	if err != nil {
		return err
	}
	batch := storage.NewBatch().WithAccount(accountID)
	suffix := storage.DocumentSuffix(storage.CollectionMailbox, mbox.ID, nil)
	if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
		return err
	}
	return ib.store.Commit(ctx, batch)
}
