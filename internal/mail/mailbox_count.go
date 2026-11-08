// Denormalized per-mailbox message counts for O(1) empty checks and STATUS.
package mail

import (
	"context"
)

// setMailboxMessageCount stores an exact count (index backfill).
func (ib *Inbox) setMailboxMessageCount(ctx context.Context, accountID, mailboxID uint32, count uint32) error {
	return ib.update(ctx, func(t *txn) error {
		mbox, err := t.mailbox(accountID, mailboxID)
		if err != nil {
			return err
		}
		mbox.MessageCount = count
		return t.putMailbox(accountID, mbox)
	})
}

func (ib *Inbox) indexMessageCount(ctx context.Context, accountID, mailboxID uint32) (uint32, error) {
	ids, err := ib.ListMailboxIndexEmailIDs(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}
	return uint32(len(ids)), nil
}
