// IMAP CONDSTORE modification sequence allocation per mailbox.
package mail

import (
	"context"

	"github.com/BeaverMail/beaver/internal/storage"
)

// allocateModSeq returns the next MODSEQ for mailboxID and updates HighestModSeq on the mailbox record.
func (ib *Inbox) allocateModSeq(ctx context.Context, accountID, mailboxID uint32) (uint64, error) {
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}
	next := mbox.HighestModSeq + 1
	if next == 0 {
		next = 1
	}
	mbox.HighestModSeq = next
	if err := ib.saveMailbox(ctx, accountID, mbox); err != nil {
		return 0, err
	}
	return next, nil
}

// HighestModSeq returns the stored highest MODSEQ for mailboxID (0 when unused).
func (ib *Inbox) HighestModSeq(ctx context.Context, accountID, mailboxID uint32) (uint64, error) {
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}
	return mbox.HighestModSeq, nil
}

func (ib *Inbox) saveMailbox(ctx context.Context, accountID uint32, mbox storage.Mailbox) error {
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

// SetFlagsIfUnchanged updates flags when UNCHANGEDSINCE allows it and bumps MODSEQ on change.
func (ib *Inbox) SetFlagsIfUnchanged(ctx context.Context, accountID, emailID uint32, set, clear uint32, unchangedSince uint64) (applied bool, meta storage.EmailMeta, err error) {
	meta, err = ib.GetMeta(ctx, accountID, emailID)
	if err != nil {
		return false, storage.EmailMeta{}, err
	}
	newFlags := (meta.Flags & ^clear) | set
	if newFlags == meta.Flags {
		return true, meta, nil
	}
	if unchangedSince > 0 && meta.ModSeq > unchangedSince {
		return false, meta, nil
	}
	modSeq, err := ib.allocateModSeq(ctx, accountID, meta.MailboxID)
	if err != nil {
		return false, storage.EmailMeta{}, err
	}
	meta.Flags = newFlags
	meta.ModSeq = modSeq
	wire, err := storage.MarshalPersist(nil, 1, meta)
	if err != nil {
		return false, storage.EmailMeta{}, err
	}
	batch := storage.NewBatch().WithAccount(accountID)
	suffix := storage.DocumentSuffix(storage.CollectionEmail, emailID, nil)
	if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
		return false, storage.EmailMeta{}, err
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
		return false, storage.EmailMeta{}, err
	}
	return true, meta, nil
}
