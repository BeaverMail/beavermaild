// Mailbox email index maintenance in SubspaceIndex.
package mail

import (
	"context"
	"errors"
	"sort"

	"github.com/BeaverMail/beaver/internal/storage"
)

func (ib *Inbox) queueMailboxIndexAdd(batch *storage.Batch, mailboxID, emailID uint32) error {
	if emailID == storage.MailboxIndexSentinelEmailID {
		return nil
	}
	return batch.Set(storage.SubspaceIndex, storage.MailboxIndexSuffix(mailboxID, emailID), storage.MailboxIndexEntryValue)
}

func (ib *Inbox) queueMailboxIndexRemove(batch *storage.Batch, mailboxID, emailID uint32) error {
	if emailID == storage.MailboxIndexSentinelEmailID {
		return nil
	}
	return batch.Delete(storage.SubspaceIndex, storage.MailboxIndexSuffix(mailboxID, emailID))
}

func (ib *Inbox) queueMailboxIndexReady(batch *storage.Batch, mailboxID uint32) error {
	return batch.Set(storage.SubspaceIndex, storage.MailboxIndexSuffix(mailboxID, storage.MailboxIndexSentinelEmailID), storage.MailboxIndexEntryValue)
}

func (ib *Inbox) mailboxIndexReady(ctx context.Context, accountID, mailboxID uint32) (bool, error) {
	key := storage.AppendMailboxIndexKey(nil, accountID, mailboxID, storage.MailboxIndexSentinelEmailID)
	_, err := ib.store.Get(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// backfillMailboxIndex builds SubspaceIndex rows from a one-time full-account scan.
func (ib *Inbox) backfillMailboxIndex(ctx context.Context, accountID, mailboxID uint32) error {
	msgs, err := ib.listAccountEmailsInMailbox(ctx, accountID, mailboxID)
	if err != nil {
		return err
	}
	batch := storage.NewBatch().WithAccount(accountID)
	for _, m := range msgs {
		if err := ib.queueMailboxIndexAdd(batch, mailboxID, m.UID); err != nil {
			return err
		}
	}
	if err := ib.queueMailboxIndexReady(batch, mailboxID); err != nil {
		return err
	}
	return ib.store.Commit(ctx, batch)
}

func (ib *Inbox) listFromMailboxIndex(ctx context.Context, accountID, mailboxID uint32) ([]Message, error) {
	from, to := storage.MailboxIndexRange(accountID, mailboxID)
	var out []Message
	err := ib.store.Iterate(ctx, from, to, func(k, _ []byte) error {
		emailID, err := storage.EmailIDFromMailboxIndexKey(k)
		if err != nil {
			return err
		}
		if emailID == storage.MailboxIndexSentinelEmailID {
			return nil
		}
		meta, err := ib.GetMeta(ctx, accountID, emailID)
		if err != nil {
			return err
		}
		if meta.MailboxID != mailboxID {
			return nil
		}
		out = append(out, Message{UID: emailID, Meta: meta})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

// listAccountEmailsInMailbox scans all account emails and filters by mailbox (legacy path for backfill).
func (ib *Inbox) listAccountEmailsInMailbox(ctx context.Context, accountID, mailboxID uint32) ([]Message, error) {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceMail, accountID, 0, byte(storage.CollectionEmail), 6)
	to := storage.AppendKey(nil, storage.SubspaceMail, accountID, ^uint32(0), byte(storage.CollectionEmail), nil)

	var out []Message
	err := ib.store.Iterate(ctx, from, to, func(k, v []byte) error {
		parts, err := storage.DecodeKey(k)
		if err != nil {
			return err
		}
		if parts.Collection != byte(storage.CollectionEmail) || len(parts.Suffix) > 0 {
			return nil
		}
		var meta storage.EmailMeta
		if err := storage.UnmarshalPersist(v, &meta); err != nil {
			return err
		}
		if meta.MailboxID != mailboxID {
			return nil
		}
		out = append(out, Message{UID: parts.DocumentID, Meta: meta})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}
