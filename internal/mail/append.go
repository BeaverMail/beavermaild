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
func (ib *Inbox) Append(ctx context.Context, accountID, mailboxID uint32, raw []byte, flags uint32) (uint32, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("mail: empty message")
	}
	if len(raw) > MaxAppendBytes {
		return 0, fmt.Errorf("mail: message too large")
	}
	if _, err := ib.mailboxRecord(ctx, accountID, mailboxID); err != nil {
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

	meta := storage.EmailMeta{
		Version:    1,
		MailboxID:  mailboxID,
		ReceivedAt: time.Now().Unix(),
		Size:       uint32(len(raw)),
		Flags:      flags | FlagRecent,
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
	if err := ib.store.Commit(ctx, batch); err != nil {
		return 0, err
	}
	return emailID, nil
}
