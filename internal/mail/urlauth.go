// IMAP URLAUTH (RFC 4467) mailbox access keys.
package mail

import (
	"context"
	"crypto/rand"
)

// URLAuthKey returns the URLAUTH access key of a mailbox, creating it when create is set; it is
// nil when the mailbox has none.
func (ib *Inbox) URLAuthKey(ctx context.Context, accountID, mailboxID uint32, create bool) ([]byte, error) {
	rec, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil || len(rec.URLAuthKey) > 0 || !create {
		return rec.URLAuthKey, err
	}
	var key []byte
	err = ib.update(ctx, accountID, func(t *txn) error {
		rec, err := t.mailbox(accountID, mailboxID)
		if err != nil {
			return err
		}
		if len(rec.URLAuthKey) == 0 { // another session may have created it meanwhile
			rec.URLAuthKey = make([]byte, 32)
			if _, err := rand.Read(rec.URLAuthKey); err != nil {
				return err
			}
			if err := t.putMailbox(accountID, rec); err != nil {
				return err
			}
		}
		key = rec.URLAuthKey
		return nil
	})
	return key, err
}

// ResetURLAuthKeys drops the URLAUTH keys of the given mailboxes, so every URL authorized with
// them stops working (RESETKEY).
func (ib *Inbox) ResetURLAuthKeys(ctx context.Context, accountID uint32, mailboxIDs []uint32) error {
	return ib.update(ctx, accountID, func(t *txn) error {
		for _, id := range mailboxIDs {
			rec, err := t.mailbox(accountID, id)
			if err != nil {
				return err
			}
			if len(rec.URLAuthKey) == 0 {
				continue
			}
			rec.URLAuthKey = nil
			if err := t.putMailbox(accountID, rec); err != nil {
				return err
			}
		}
		return nil
	})
}
