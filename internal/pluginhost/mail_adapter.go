// Mail store adapter for plugin host ingest (delegates to internal/mail).
package pluginhost

import (
	"context"
	"encoding/hex"

	"github.com/BeaverMail/beaver/internal/runtime"
)

// HostMail wraps runtime.Stack for CLI batch ingest in the host process.
type HostMail struct {
	stack *runtime.Stack
}

// NewHostMail returns a mail adapter over an opened stack.
func NewHostMail(stack *runtime.Stack) *HostMail {
	return &HostMail{stack: stack}
}

// AccountID resolves an existing account email.
func (h *HostMail) AccountID(ctx context.Context, email string) (uint32, error) {
	return h.stack.AccountID(ctx, email)
}

// EnsureMailboxes creates default folders when missing.
func (h *HostMail) EnsureMailboxes(ctx context.Context, accountID uint32) error {
	return h.stack.Inbox.EnsureMailboxes(ctx, accountID)
}

// ResolveMailbox looks up or creates a folder by IMAP name.
func (h *HostMail) ResolveMailbox(ctx context.Context, accountID uint32, imapName string) (uint32, error) {
	ref, err := h.stack.Inbox.ResolveMailbox(ctx, accountID, imapName)
	if err == nil {
		return ref.ID, nil
	}
	created, err := h.stack.Inbox.CreateMailbox(ctx, accountID, imapName)
	if err != nil {
		return 0, err
	}
	return created.ID, nil
}

// Append stores one message.
func (h *HostMail) Append(ctx context.Context, accountID, mailboxID uint32, raw []byte, flags uint32, receivedAt int64) error {
	_, err := h.stack.Inbox.Append(ctx, accountID, mailboxID, raw, flags, receivedAt)
	return err
}

// ClearRecent clears \\Recent on all messages in a mailbox.
func (h *HostMail) ClearRecent(ctx context.Context, accountID, mailboxID uint32) error {
	_, err := h.stack.Inbox.ClearRecentFlags(ctx, accountID, mailboxID)
	return err
}

// AccountHashIndex maps Blake3 hex hash to the first IMAP mailbox that holds the message.
func (h *HostMail) AccountHashIndex(ctx context.Context, accountID uint32) (map[string]string, error) {
	boxes, err := h.stack.Inbox.ListMailboxes(ctx, accountID)
	if err != nil {
		return nil, err
	}
	known := make(map[string]string)
	for _, b := range boxes {
		msgs, err := h.stack.Inbox.List(ctx, accountID, b.ID)
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if !m.Meta.HasBlob() {
				continue
			}
			hash := hex.EncodeToString(m.Meta.BlobHash[:])
			if _, ok := known[hash]; !ok {
				known[hash] = b.Name
			}
		}
	}
	return known, nil
}
