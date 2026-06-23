// Move and copy messages between mailboxes.
package mail

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/BeaverMail/beaver/internal/storage"
)

// ErrMailboxExists is returned when CREATE targets an existing folder name.
var ErrMailboxExists = errors.New("mail: mailbox exists")

// ErrSystemMailbox is returned when a built-in folder cannot be deleted.
var ErrSystemMailbox = errors.New("mail: system mailbox")

// ErrMailboxNotEmpty is returned when DELETE targets a non-empty folder.
var ErrMailboxNotEmpty = errors.New("mail: mailbox not empty")

// MoveMessages updates MailboxID for each emailID into destMailboxID.
func (ib *Inbox) MoveMessages(ctx context.Context, accountID uint32, emailIDs []uint32, destMailboxID uint32) error {
	if len(emailIDs) == 0 {
		return nil
	}
	if _, err := ib.mailboxRecord(ctx, accountID, destMailboxID); err != nil {
		return err
	}
	batch := storage.NewBatch().WithAccount(accountID)
	for _, id := range emailIDs {
		meta, err := ib.GetMeta(ctx, accountID, id)
		if err != nil {
			return err
		}
		meta.MailboxID = destMailboxID
		wire, err := storage.MarshalPersist(nil, 1, meta)
		if err != nil {
			return err
		}
		suffix := storage.DocumentSuffix(storage.CollectionEmail, id, nil)
		if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
			return err
		}
	}
	return ib.store.Commit(ctx, batch)
}

// CopyMessages duplicates messages into destMailboxID (shared blob hash).
func (ib *Inbox) CopyMessages(ctx context.Context, accountID uint32, emailIDs []uint32, destMailboxID uint32) ([]uint32, error) {
	if len(emailIDs) == 0 {
		return nil, nil
	}
	if _, err := ib.mailboxRecord(ctx, accountID, destMailboxID); err != nil {
		return nil, err
	}
	var newIDs []uint32
	batch := storage.NewBatch().WithAccount(accountID)
	for _, srcID := range emailIDs {
		meta, err := ib.GetMeta(ctx, accountID, srcID)
		if err != nil {
			return nil, err
		}
		newID, err := ib.nextEmailID(ctx, accountID)
		if err != nil {
			return nil, err
		}
		meta.MailboxID = destMailboxID
		wire, err := storage.MarshalPersist(nil, 1, meta)
		if err != nil {
			return nil, err
		}
		suffix := storage.DocumentSuffix(storage.CollectionEmail, newID, nil)
		if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
			return nil, err
		}
		newIDs = append(newIDs, newID)
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
		return nil, err
	}
	return newIDs, nil
}

func (ib *Inbox) mailboxRecord(ctx context.Context, accountID, mailboxID uint32) (storage.Mailbox, error) {
	key := storage.AppendKey(nil, storage.SubspaceMail, accountID, mailboxID, byte(storage.CollectionMailbox), nil)
	wire, err := ib.store.Get(ctx, key)
	if err != nil {
		return storage.Mailbox{}, err
	}
	var mbox storage.Mailbox
	if err := storage.UnmarshalPersist(wire, &mbox); err != nil {
		return storage.Mailbox{}, err
	}
	return mbox, nil
}

// MailboxStatus holds IMAP STATUS counters for one folder.
type MailboxStatus struct {
	Messages    uint32
	Unseen      uint32
	UIDNext     uint32
	UIDValidity uint32
}

// Status returns IMAP STATUS fields for mailboxID.
func (ib *Inbox) Status(ctx context.Context, accountID, mailboxID uint32) (MailboxStatus, error) {
	mbox, err := ib.mailboxRecord(ctx, accountID, mailboxID)
	if err != nil {
		return MailboxStatus{}, err
	}
	msgs, err := ib.List(ctx, accountID, mailboxID)
	if err != nil {
		return MailboxStatus{}, err
	}
	var unseen uint32
	var uidNext uint32 = 1
	for _, m := range msgs {
		if m.Meta.Flags&FlagSeen == 0 {
			unseen++
		}
		if m.UID >= uidNext {
			uidNext = m.UID + 1
		}
	}
	return MailboxStatus{
		Messages:    uint32(len(msgs)),
		Unseen:      unseen,
		UIDNext:     uidNext,
		UIDValidity: mbox.UIDValidity,
	}, nil
}

// CreateMailbox adds a user folder and returns its record.
func (ib *Inbox) CreateMailbox(ctx context.Context, accountID uint32, name string) (Mailbox, error) {
	name = stringsTrimMailboxName(name)
	if name == "" {
		return Mailbox{}, fmt.Errorf("mail: empty mailbox name")
	}
	if _, err := ib.ResolveMailbox(ctx, accountID, name); err == nil {
		return Mailbox{}, ErrMailboxExists
	} else if !errors.Is(err, storage.ErrNotFound) {
		return Mailbox{}, err
	}
	id, err := ib.nextCustomMailboxID(ctx, accountID)
	if err != nil {
		return Mailbox{}, err
	}
	mbox := storage.Mailbox{ID: id, Name: name, UIDNext: 1, UIDValidity: 1}
	wire, err := storage.MarshalPersist(nil, 1, mbox)
	if err != nil {
		return Mailbox{}, err
	}
	batch := storage.NewBatch().WithAccount(accountID)
	suffix := storage.DocumentSuffix(storage.CollectionMailbox, id, nil)
	if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
		return Mailbox{}, err
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
		return Mailbox{}, err
	}
	return Mailbox{ID: id, Name: name, UIDValidity: 1}, nil
}

// DeleteMailbox removes an empty non-system folder.
func (ib *Inbox) DeleteMailbox(ctx context.Context, accountID, mailboxID uint32) error {
	if mailboxID <= TrashMailboxID {
		return ErrSystemMailbox
	}
	msgs, err := ib.List(ctx, accountID, mailboxID)
	if err != nil {
		return err
	}
	if len(msgs) > 0 {
		return ErrMailboxNotEmpty
	}
	batch := storage.NewBatch().WithAccount(accountID)
	suffix := storage.DocumentSuffix(storage.CollectionMailbox, mailboxID, nil)
	if err := batch.Delete(storage.SubspaceMail, suffix); err != nil {
		return err
	}
	return ib.store.Commit(ctx, batch)
}

func (ib *Inbox) nextCustomMailboxID(ctx context.Context, accountID uint32) (uint32, error) {
	records, err := ib.listMailboxRecords(ctx, accountID)
	if err != nil {
		return 0, err
	}
	var max uint32 = TrashMailboxID
	for _, m := range records {
		if m.ID > max {
			max = m.ID
		}
	}
	return max + 1, nil
}

func stringsTrimMailboxName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) >= 2 && name[0] == '"' && name[len(name)-1] == '"' {
		name = name[1 : len(name)-1]
	}
	return strings.TrimSpace(name)
}
