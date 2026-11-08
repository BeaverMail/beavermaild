// Append stores a client-uploaded message into a mailbox (IMAP APPEND).
package mail

import (
	"context"
	"fmt"
	"time"
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
	if receivedAt <= 0 {
		receivedAt = time.Now().Unix()
	}
	return ib.storeMessage(ctx, accountID, mailboxID, raw, flags, receivedAt)
}
