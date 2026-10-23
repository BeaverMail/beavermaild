// IMAP CONDSTORE modification sequence allocation per mailbox.
package mail

import (
	"context"
	"strings"

	"github.com/BeaverMail/beaver/internal/storage"
)

// HighestModSeq returns the stored highest MODSEQ for mailboxID (0 when unused).
func (ib *Inbox) HighestModSeq(ctx context.Context, accountID, mailboxID uint32) (uint64, error) {
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}
	return mbox.HighestModSeq, nil
}

// SetFlagsIfUnchanged updates flags/keywords when UNCHANGEDSINCE allows it and bumps MODSEQ on change.
func (ib *Inbox) SetFlagsIfUnchanged(ctx context.Context, accountID, emailID uint32, set, clear uint32, kwAdd, kwRemove []string, unchangedSince uint64) (applied bool, meta storage.EmailMeta, err error) {
	err = ib.update(ctx, func(t *txn) error {
		meta, err = t.meta(accountID, emailID)
		if err != nil {
			return err
		}
		before := meta
		meta.Flags = (meta.Flags & ^clear) | set
		ApplyKeywords(&meta, kwAdd, kwRemove)
		if unchangedSince > 0 && before.ModSeq > unchangedSince {
			applied, meta = false, before
			return nil
		}
		applied = true
		if meta.Flags == before.Flags && keywordsEqual(meta.Keywords, before.Keywords) {
			return nil
		}
		mbox, err := t.mailbox(accountID, meta.MailboxID)
		if err != nil {
			return err
		}
		meta.ModSeq = nextModSeq(&mbox)
		if err := t.putMailbox(accountID, mbox); err != nil {
			return err
		}
		return t.putMeta(accountID, emailID, meta)
	})
	if err != nil {
		return false, storage.EmailMeta{}, err
	}
	return applied, meta, nil
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
