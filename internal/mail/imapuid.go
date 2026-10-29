// Per-mailbox IMAP UID allocation and legacy store backfill.
package mail

import (
	"context"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// IMAPUID returns the IMAP UID for a message (legacy rows use emailID until backfill).
func IMAPUID(emailID uint32, meta storage.EmailMeta) uint32 {
	if meta.IMAPUID != 0 {
		return meta.IMAPUID
	}
	return emailID
}

func messageFromMeta(emailID uint32, meta storage.EmailMeta) Message {
	return Message{
		EmailID: emailID,
		UID:     IMAPUID(emailID, meta),
		Meta:    meta,
	}
}

// ensureIMAPUIDBackfill assigns legacy IMAPUID=emailID and sets UIDNext for existing messages.
func (ib *Inbox) ensureIMAPUIDBackfill(ctx context.Context, accountID, mailboxID uint32) error {
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil || mbox.UIDSeqInit {
		return err
	}
	return ib.update(ctx, func(t *txn) error {
		mbox, err := t.mailbox(accountID, mailboxID)
		if err != nil || mbox.UIDSeqInit {
			return err
		}
		if err := t.initUIDs(accountID, &mbox); err != nil {
			return err
		}
		return t.putMailbox(accountID, mbox)
	})
}

// MailboxUIDNext returns the next unassigned IMAP UID for mailboxID (RFC 3501 UIDNEXT).
func (ib *Inbox) MailboxUIDNext(ctx context.Context, accountID, mailboxID uint32) (uint32, error) {
	if err := ib.ensureIMAPUIDBackfill(ctx, accountID, mailboxID); err != nil {
		return 0, err
	}
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}
	if mbox.UIDNext == 0 {
		return 1, nil
	}
	return mbox.UIDNext, nil
}
