// Account mailboxes in SubspaceMail (IMAP/JMAP).
package mail

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/BeaverMail/beaver/internal/storage"
)

const (
	InboxMailboxID  uint32 = 1
	SentMailboxID   uint32 = 2
	TrashMailboxID  uint32 = 3
	DraftsMailboxID uint32 = 4
)

// Mailbox is one IMAP-selectable folder for an account.
type Mailbox struct {
	ID            uint32
	Name          string
	UIDValidity   uint32
	HighestModSeq uint64
	Subscribed    bool
}

var defaultMailboxDefs = []struct {
	id   uint32
	name string
	role string
}{
	{InboxMailboxID, "INBOX", "inbox"},
	{SentMailboxID, "Sent", "sent"},
	{TrashMailboxID, "Trash", "trash"},
	{DraftsMailboxID, "Drafts", "drafts"},
}

// ListMailboxes returns account folders, ensuring defaults exist.
func (ib *Inbox) ListMailboxes(ctx context.Context, accountID uint32) ([]Mailbox, error) {
	if err := ib.EnsureMailboxes(ctx, accountID); err != nil {
		return nil, err
	}
	records, err := ib.listMailboxRecords(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Mailbox, len(records))
	for i, m := range records {
		out[i] = Mailbox{
			ID:            m.ID,
			Name:          m.Name,
			UIDValidity:   m.UIDValidity,
			HighestModSeq: m.HighestModSeq,
			Subscribed:    mailboxSubscribed(m),
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ResolveMailbox maps an IMAP mailbox name to a folder record.
func (ib *Inbox) ResolveMailbox(ctx context.Context, accountID uint32, imapName string) (Mailbox, error) {
	if err := ib.EnsureMailboxes(ctx, accountID); err != nil {
		return Mailbox{}, err
	}
	imapName = strings.TrimSpace(imapName)
	if imapName == "" {
		return Mailbox{}, fmt.Errorf("mail: empty mailbox name")
	}
	records, err := ib.listMailboxRecords(ctx, accountID)
	if err != nil {
		return Mailbox{}, err
	}
	upper := strings.ToUpper(imapName)
	for _, m := range records {
		if strings.ToUpper(m.Name) == upper {
			return Mailbox{
				ID:            m.ID,
				Name:          m.Name,
				UIDValidity:   m.UIDValidity,
				HighestModSeq: m.HighestModSeq,
				Subscribed:    mailboxSubscribed(m),
			}, nil
		}
	}
	return Mailbox{}, storage.ErrNotFound
}

// EnsureMailboxes creates INBOX, Sent, Trash, and Drafts when missing (e.g. after seed upgrade).
func (ib *Inbox) EnsureMailboxes(ctx context.Context, accountID uint32) error {
	records, err := ib.listMailboxRecords(ctx, accountID)
	if err != nil {
		return err
	}
	present := make(map[uint32]struct{}, len(records))
	for _, m := range records {
		present[m.ID] = struct{}{}
	}
	batch := storage.NewBatch().WithAccount(accountID)
	changed := false
	for _, def := range defaultMailboxDefs {
		if _, ok := present[def.id]; ok {
			continue
		}
		mbox := storage.Mailbox{
			ID:          def.id,
			Name:        def.name,
			Role:        def.role,
			UIDNext:     1,
			UIDValidity: 1,
			Subscribed:  true,
			SubSet:      true,
		}
		wire, err := storage.MarshalPersist(nil, 1, mbox)
		if err != nil {
			return err
		}
		suffix := storage.DocumentSuffix(storage.CollectionMailbox, def.id, nil)
		if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return ib.store.Commit(ctx, batch)
}

func (ib *Inbox) listMailboxRecords(ctx context.Context, accountID uint32) ([]storage.Mailbox, error) {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceMail, accountID, 0, byte(storage.CollectionMailbox), 6)
	to := storage.AppendKey(nil, storage.SubspaceMail, accountID, ^uint32(0), byte(storage.CollectionMailbox), nil)

	var out []storage.Mailbox
	err := ib.store.Iterate(ctx, from, to, func(k, v []byte) error {
		parts, err := storage.DecodeKey(k)
		if err != nil {
			return err
		}
		if parts.Collection != byte(storage.CollectionMailbox) || len(parts.Suffix) > 0 {
			return nil
		}
		var mbox storage.Mailbox
		if err := storage.UnmarshalPersist(v, &mbox); err != nil {
			return err
		}
		out = append(out, mbox)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ErrNoSuchMessage is returned when a sequence or UID does not exist in the selected mailbox.
var ErrNoSuchMessage = errors.New("mail: no such message")
