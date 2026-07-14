// Per-mailbox IMAP UID allocation and legacy store backfill.
package mail

import (
	"context"

	"github.com/BeaverMail/beaver/internal/storage"
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

// allocateIMAPUID returns the next IMAP UID for mailboxID and bumps Mailbox.UIDNext.
func (ib *Inbox) allocateIMAPUID(ctx context.Context, accountID, mailboxID uint32) (uint32, error) {
	if err := ib.ensureIMAPUIDBackfill(ctx, accountID, mailboxID); err != nil {
		return 0, err
	}
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}
	uid := mbox.UIDNext
	if uid == 0 {
		uid = 1
	}
	mbox.UIDNext = uid + 1
	if err := ib.saveMailbox(ctx, accountID, mbox); err != nil {
		return 0, err
	}
	return uid, nil
}

// ensureIMAPUIDBackfill assigns legacy IMAPUID=emailID and sets UIDNext for existing messages.
func (ib *Inbox) ensureIMAPUIDBackfill(ctx context.Context, accountID, mailboxID uint32) error {
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return err
	}
	if mbox.UIDSeqInit {
		return nil
	}

	msgs, err := ib.listAccountEmailsInMailbox(ctx, accountID, mailboxID)
	if err != nil {
		return err
	}

	batch := storage.NewBatch().WithAccount(accountID)
	var maxUID uint32
	for _, m := range msgs {
		meta := m.Meta
		if meta.IMAPUID == 0 {
			meta.IMAPUID = m.EmailID
			wire, err := storage.MarshalPersist(nil, 1, meta)
			if err != nil {
				return err
			}
			suffix := storage.DocumentSuffix(storage.CollectionEmail, m.EmailID, nil)
			if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
				return err
			}
		}
		if meta.IMAPUID > maxUID {
			maxUID = meta.IMAPUID
		}
	}

	mbox.UIDNext = maxUID + 1
	if mbox.UIDNext == 0 {
		mbox.UIDNext = 1
	}
	mbox.UIDSeqInit = true
	wire, err := storage.MarshalPersist(nil, 1, mbox)
	if err != nil {
		return err
	}
	suffix := storage.DocumentSuffix(storage.CollectionMailbox, mbox.ID, nil)
	if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
		return err
	}
	return ib.store.Commit(ctx, batch)
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
