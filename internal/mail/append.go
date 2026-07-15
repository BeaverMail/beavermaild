// Append stores a client-uploaded message into a mailbox (IMAP APPEND).
package mail

import (
	"context"
	"fmt"
	"time"

	"github.com/BeaverMail/beaver/internal/storage"
)

// MaxAppendBytes is the largest RFC 5322 blob accepted via IMAP APPEND.
const MaxAppendBytes = 32 << 20

// Append stores raw bytes in mailboxID with optional IMAP flags.
// receivedAt is Unix seconds for INTERNALDATE; when <= 0, uses the current time.
func (ib *Inbox) Append(ctx context.Context, accountID, mailboxID uint32, raw []byte, flags uint32, receivedAt int64) (uint32, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("mail: empty message")
	}
	if len(raw) > MaxAppendBytes {
		return 0, fmt.Errorf("mail: message too large")
	}
	if _, err := ib.mailboxRecord(ctx, accountID, mailboxID); err != nil {
		return 0, err
	}
	if err := ib.checkQuota(ctx, accountID, uint64(len(raw)), 1); err != nil {
		return 0, err
	}

	hash, err := ib.blobs.Put(ctx, raw)
	if err != nil {
		return 0, err
	}

	emailID, err := ib.nextEmailID(ctx, accountID)
	if err != nil {
		return 0, err
	}

	imapUID, err := ib.allocateIMAPUID(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}

	modSeq, err := ib.allocateModSeq(ctx, accountID, mailboxID)
	if err != nil {
		return 0, err
	}

	if receivedAt <= 0 {
		receivedAt = time.Now().Unix()
	}
	meta := storage.EmailMeta{
		Version:    1,
		MailboxID:  mailboxID,
		ReceivedAt: receivedAt,
		Size:       uint32(len(raw)),
		Flags:      flags | FlagRecent,
		ModSeq:     modSeq,
		IMAPUID:    imapUID,
		BlobHash:   hash,
	}
	wire, err := storage.MarshalPersist(nil, 1, meta)
	if err != nil {
		return 0, err
	}

	batch := storage.NewBatch().WithAccount(accountID)
	suffix := storage.DocumentSuffix(storage.CollectionEmail, emailID, nil)
	if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
		return 0, err
	}
	if err := ib.queueMailboxIndexAdd(batch, mailboxID, emailID); err != nil {
		return 0, err
	}
	if err := ib.queueMailboxIndexReady(batch, mailboxID); err != nil {
		return 0, err
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
		return 0, err
	}
	if err := ib.bumpMailboxMessageCount(ctx, accountID, mailboxID, 1); err != nil {
		return 0, err
	}
	if err := ib.addQuotaUsage(ctx, accountID, uint64(len(raw)), 1); err != nil {
		return 0, err
	}
	return emailID, nil
}
