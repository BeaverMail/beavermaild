// List and load mailbox messages from the KV store and blob filesystem.
package mail

import (
	"context"
	"sort"

	"github.com/BeaverMail/beaver/internal/storage"
)

// Message is one email in a mailbox (UID equals the email document id).
type Message struct {
	UID  uint32
	Meta storage.EmailMeta
}

// List returns messages in mailboxID for accountID, sorted by UID ascending.
func (ib *Inbox) List(ctx context.Context, accountID, mailboxID uint32) ([]Message, error) {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceMail, accountID, 0, byte(storage.CollectionEmail), 6)
	to := storage.AppendKey(nil, storage.SubspaceMail, accountID, ^uint32(0), byte(storage.CollectionEmail), nil)

	var out []Message
	err := ib.store.Iterate(ctx, from, to, func(k, v []byte) error {
		parts, err := storage.DecodeKey(k)
		if err != nil {
			return err
		}
		if parts.Collection != byte(storage.CollectionEmail) || len(parts.Suffix) > 0 {
			return nil
		}
		var meta storage.EmailMeta
		if err := storage.UnmarshalPersist(v, &meta); err != nil {
			return err
		}
		if meta.MailboxID != mailboxID {
			return nil
		}
		out = append(out, Message{UID: parts.DocumentID, Meta: meta})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

// LoadRaw returns the RFC 5322 bytes for meta (blob hash required).
func (ib *Inbox) LoadRaw(ctx context.Context, meta storage.EmailMeta) ([]byte, error) {
	if !meta.HasBlob() {
		return nil, storage.ErrNotFound
	}
	return ib.blobs.Get(ctx, meta.BlobHash)
}
