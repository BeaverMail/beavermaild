// Message deletion from a mailbox (IMAP EXPUNGE).
package mail

import (
	"context"
	"errors"
	"slices"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// DeleteMessage removes email metadata. The blob file stays until blob.GC finds it unreferenced:
// checking references here would scan every message, and could race an APPEND of the same content.
func (ib *Inbox) DeleteMessage(ctx context.Context, accountID, emailID uint32) error {
	return ib.update(ctx, accountID, func(t *txn) error {
		meta, err := t.meta(accountID, emailID)
		if err != nil {
			return err
		}
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
}

// writeBatch bounds the messages one multi-message transaction (EXPUNGE, STORE) touches.
const writeBatch = 256

// ExpungeMessages deletes the given messages that are still in mailboxID and flagged \Deleted, as
// checked in the same transaction (another session may have moved them or cleared the flag), and
// returns the IDs it deleted. One transaction per batch: under load each one waits for the
// account write lock, so a per-message transaction made EXPUNGE wait in line once per message.
func (ib *Inbox) ExpungeMessages(ctx context.Context, accountID, mailboxID uint32, emailIDs []uint32) ([]uint32, error) {
	var out []uint32
	for chunk := range slices.Chunk(emailIDs, writeBatch) {
		var done []uint32
		err := ib.update(ctx, accountID, func(t *txn) error {
			done = done[:0]
			mbox, err := t.mailbox(accountID, mailboxID)
			if err != nil {
				return err
			}
			var bytes int64
			for _, id := range chunk {
				meta, err := t.meta(accountID, id)
				if errors.Is(err, storage.ErrNotFound) {
					continue // already expunged elsewhere
				}
				if err != nil {
					return err
				}
				if meta.MailboxID != mailboxID || meta.Flags&FlagDeleted == 0 {
					continue
				}
				t.del(emailKey(accountID, id))
				t.indexRemove(accountID, mailboxID, id)
				bytes += int64(meta.Size)
				done = append(done, id)
			}
			if len(done) == 0 {
				return nil
			}
			nextModSeq(&mbox)
			if err := t.bumpCount(accountID, &mbox, -int32(len(done))); err != nil {
				return err
			}
			if err := t.putMailbox(accountID, mbox); err != nil {
				return err
			}
			return t.addQuota(accountID, -bytes, -int32(len(done)))
		})
		if errors.Is(err, storage.ErrNotFound) {
			return out, nil // the mailbox itself was deleted
		}
		if err != nil {
			return out, err
		}
		out = append(out, done...)
	}
	return out, nil
}
