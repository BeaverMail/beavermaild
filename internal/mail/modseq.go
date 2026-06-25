// IMAP CONDSTORE modification sequence allocation per mailbox.
package mail

import (
	"context"
	"strings"

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

// SetFlagsIfUnchanged updates flags/keywords when UNCHANGEDSINCE allows it and bumps MODSEQ on change.
func (ib *Inbox) SetFlagsIfUnchanged(ctx context.Context, accountID, emailID uint32, set, clear uint32, kwAdd, kwRemove []string, unchangedSince uint64) (applied bool, meta storage.EmailMeta, err error) {
	meta, err = ib.GetMeta(ctx, accountID, emailID)
	if err != nil {
		return false, storage.EmailMeta{}, err
	}
	before := meta
	meta.Flags = (meta.Flags & ^clear) | set
	ApplyKeywords(&meta, kwAdd, kwRemove)
	if unchangedSince > 0 && before.ModSeq > unchangedSince {
		return false, before, nil
	}
	if meta.Flags == before.Flags && keywordsEqual(meta.Keywords, before.Keywords) {
		return true, meta, nil
	}
	modSeq, err := ib.allocateModSeq(ctx, accountID, meta.MailboxID)
	if err != nil {
		return false, storage.EmailMeta{}, err
	}
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

func keywordsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}
