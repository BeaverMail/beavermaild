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
		if err := ib.queueMailboxIndexAdd(batch, mailboxID, m.EmailID); err != nil {
			return err
		}
	}
	if err := ib.queueMailboxIndexReady(batch, mailboxID); err != nil {
		return err
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
		return err
	}
	return ib.setMailboxMessageCount(ctx, accountID, mailboxID, uint32(len(msgs)))
}

func (ib *Inbox) listFromMailboxIndex(ctx context.Context, accountID, mailboxID uint32) ([]Message, error) {
	emailIDs, err := ib.collectMailboxIndexUIDs(ctx, accountID, mailboxID)
	if err != nil {
		return nil, err
	}
	if len(emailIDs) == 0 {
		return nil, nil
	}
	metas, err := ib.loadEmailMetaBatch(ctx, accountID, emailIDs)
	if err != nil {
		return nil, err
	}
	out := make([]Message, 0, len(emailIDs))
	for _, emailID := range emailIDs {
		meta, ok := metas[emailID]
		if !ok {
			return nil, storage.ErrNotFound
		}
		if meta.MailboxID != mailboxID {
			continue
		}
		out = append(out, messageFromMeta(emailID, meta))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

// ListMailboxIndexEmailIDs returns sorted email document ids indexed for mailboxID.
func (ib *Inbox) ListMailboxIndexEmailIDs(ctx context.Context, accountID, mailboxID uint32) ([]uint32, error) {
	uids, err := ib.collectMailboxIndexUIDs(ctx, accountID, mailboxID)
	if err != nil {
		return nil, err
	}
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	return uids, nil
}

// ListMailboxIndexUIDs returns sorted email document ids indexed for mailboxID.
func (ib *Inbox) ListMailboxIndexUIDs(ctx context.Context, accountID, mailboxID uint32) ([]uint32, error) {
	return ib.ListMailboxIndexEmailIDs(ctx, accountID, mailboxID)
}

// AppendMailboxMessages merges cached messages with batch-loaded new email ids.
func (ib *Inbox) AppendMailboxMessages(ctx context.Context, accountID, mailboxID uint32, cached []Message, newEmailIDs []uint32) ([]Message, error) {
	if len(newEmailIDs) == 0 {
		return append([]Message(nil), cached...), nil
	}
	metas, err := ib.loadEmailMetaBatch(ctx, accountID, newEmailIDs)
	if err != nil {
		return nil, err
	}
	out := append([]Message(nil), cached...)
	for _, emailID := range newEmailIDs {
		meta, ok := metas[emailID]
		if !ok {
			return nil, storage.ErrNotFound
		}
		if meta.MailboxID != mailboxID {
			continue
		}
		out = append(out, messageFromMeta(emailID, meta))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

func (ib *Inbox) collectMailboxIndexUIDs(ctx context.Context, accountID, mailboxID uint32) ([]uint32, error) {
	ready, err := ib.mailboxIndexReady(ctx, accountID, mailboxID)
	if err != nil {
		return nil, err
	}
	if !ready {
		if err := ib.backfillMailboxIndex(ctx, accountID, mailboxID); err != nil {
			return nil, err
		}
	}
	from, to := storage.MailboxIndexRange(accountID, mailboxID)
	var emailIDs []uint32
	err = ib.store.Iterate(ctx, from, to, func(k, _ []byte) error {
		emailID, err := storage.EmailIDFromMailboxIndexKey(k)
		if err != nil {
			return err
		}
		if emailID == storage.MailboxIndexSentinelEmailID {
			return nil
		}
		emailIDs = append(emailIDs, emailID)
		return nil
	})
	return emailIDs, err
}

func (ib *Inbox) loadEmailMetaBatch(ctx context.Context, accountID uint32, emailIDs []uint32) (map[uint32]storage.EmailMeta, error) {
	if len(emailIDs) == 0 {
		return nil, nil
	}
	keys := make([][]byte, len(emailIDs))
	for i, emailID := range emailIDs {
		keys[i] = storage.AppendKey(nil, storage.SubspaceMail, accountID, emailID, byte(storage.CollectionEmail), nil)
	}
	values, err := ib.store.GetMany(ctx, keys)
	if err != nil {
		return nil, err
	}
	out := make(map[uint32]storage.EmailMeta, len(emailIDs))
	for i, emailID := range emailIDs {
		wire, ok := values[string(keys[i])]
		if !ok {
			return nil, storage.ErrNotFound
		}
		var meta storage.EmailMeta
		if err := storage.UnmarshalPersist(wire, &meta); err != nil {
			return nil, err
		}
		out[emailID] = meta
	}
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
		out = append(out, messageFromMeta(parts.DocumentID, meta))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}
