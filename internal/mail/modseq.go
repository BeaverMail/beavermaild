// IMAP CONDSTORE modification sequence allocation per mailbox.
package mail

import (
	"context"
	"errors"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// HighestModSeq returns the stored highest MODSEQ for mailboxID (0 when unused).
func (ib *Inbox) HighestModSeq(ctx context.Context, accountID, mailboxID uint32) (uint64, error) {
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}
	return mbox.HighestModSeq, nil
}

// SetFlagsIfUnchanged updates flags/keywords when UNCHANGEDSINCE allows it and bumps MODSEQ on
// change. storage.ErrNotFound means the message is gone.
func (ib *Inbox) SetFlagsIfUnchanged(ctx context.Context, accountID, emailID uint32, set, clear uint32, kwAdd, kwRemove []string, unchangedSince uint64) (applied bool, meta storage.EmailMeta, err error) {
	res, err := ib.SetFlagsMany(ctx, accountID, []uint32{emailID}, set, clear, kwAdd, kwRemove, unchangedSince)
	if err != nil {
		return false, storage.EmailMeta{}, err
	}
	if res[0].Gone {
		return false, storage.EmailMeta{}, storage.ErrNotFound
	}
	return res[0].Applied, res[0].Meta, nil
}

// FlagResult is the outcome of a flag update for one message.
type FlagResult struct {
	Applied bool              // false: UNCHANGEDSINCE refused it, Meta is the unchanged metadata
	Gone    bool              // expunged meanwhile
	Meta    storage.EmailMeta // metadata after the update
}

// SetFlagsMany applies one flag/keyword update to emailIDs, one transaction per batch: under load
// each transaction waits for the account write lock, so one per message made a STORE on a range
// wait in line once per message. The results follow emailIDs.
func (ib *Inbox) SetFlagsMany(ctx context.Context, accountID uint32, emailIDs []uint32, setBits, clearBits uint32, kwAdd, kwRemove []string, unchangedSince uint64) ([]FlagResult, error) {
	out := make([]FlagResult, len(emailIDs))
	for start := 0; start < len(emailIDs); start += writeBatch {
		end := min(start+writeBatch, len(emailIDs))
		chunk, res := emailIDs[start:end], out[start:end]
		err := ib.update(ctx, accountID, func(t *txn) error {
			clear(res)
			boxes := map[uint32]*storage.Mailbox{}
			for i, id := range chunk {
				meta, err := t.meta(accountID, id)
				if errors.Is(err, storage.ErrNotFound) {
					res[i].Gone = true
					continue
				}
				if err != nil {
					return err
				}
				before := meta
				meta.Flags = (meta.Flags &^ clearBits) | setBits
				ApplyKeywords(&meta, kwAdd, kwRemove)
				if unchangedSince > 0 && before.ModSeq > unchangedSince {
					res[i].Meta = before
					continue
				}
				res[i].Applied, res[i].Meta = true, meta
				if meta.Flags == before.Flags && keywordsEqual(meta.Keywords, before.Keywords) {
					continue
				}
				mbox := boxes[meta.MailboxID]
				if mbox == nil {
					m, err := t.mailbox(accountID, meta.MailboxID)
					if err != nil {
						return err
					}
					mbox = &m
					boxes[meta.MailboxID] = mbox
				}
				meta.ModSeq = nextModSeq(mbox)
				res[i].Meta = meta
				if err := t.putMeta(accountID, id, meta); err != nil {
					return err
				}
			}
			for _, mbox := range boxes {
				if err := t.putMailbox(accountID, *mbox); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
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
