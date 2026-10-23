// Move and copy messages between mailboxes.
package mail

import (
	"context"
	"errors"
	"strings"

	"github.com/BeaverMail/beaver/internal/storage"
)

// ErrMailboxExists is returned when CREATE targets an existing folder name.
var ErrMailboxExists = errors.New("mail: mailbox exists")

// ErrSystemMailbox is returned when a built-in folder cannot be deleted.
var ErrSystemMailbox = errors.New("mail: system mailbox")

// ErrMailboxNotEmpty is returned when DELETE targets a non-empty folder.
var ErrMailboxNotEmpty = errors.New("mail: mailbox not empty")

// MoveMessages updates MailboxID for each emailID into destMailboxID and assigns new IMAP UIDs.
func (ib *Inbox) MoveMessages(ctx context.Context, accountID uint32, emailIDs []uint32, destMailboxID uint32) ([]uint32, error) {
	if len(emailIDs) == 0 {
		return nil, nil
	}
	var destUIDs []uint32
	err := ib.update(ctx, func(t *txn) error {
		destUIDs = make([]uint32, 0, len(emailIDs))
		boxes := newTxnMailboxes(t, accountID)
		dest, err := boxes.get(destMailboxID)
		if err != nil {
			return err
		}
		for _, id := range emailIDs {
			meta, err := t.meta(accountID, id)
			if err != nil {
				return err
			}
			if _, err := boxes.get(meta.MailboxID); err != nil {
				return err
			}
			boxes.delta[meta.MailboxID]--
			boxes.delta[destMailboxID]++
			t.indexRemove(accountID, meta.MailboxID, id)
			uid, err := t.nextUID(accountID, dest)
			if err != nil {
				return err
			}
			meta.MailboxID = destMailboxID
			meta.IMAPUID = uid
			meta.Flags &^= FlagRecent
			meta.ModSeq = nextModSeq(dest)
			if err := t.putMeta(accountID, id, meta); err != nil {
				return err
			}
			t.indexAdd(accountID, destMailboxID, id)
			destUIDs = append(destUIDs, uid)
		}
		return boxes.save()
	})
	if err != nil {
		return nil, err
	}
	return destUIDs, nil
}

// CopyMessages duplicates messages into destMailboxID (shared blob hash).
func (ib *Inbox) CopyMessages(ctx context.Context, accountID uint32, emailIDs []uint32, destMailboxID uint32) ([]uint32, []uint32, error) {
	if len(emailIDs) == 0 {
		return nil, nil, nil
	}
	if _, err := ib.mailboxRecord(ctx, accountID, destMailboxID); err != nil {
		return nil, nil, err
	}
	var addBytes uint64
	for _, srcID := range emailIDs {
		meta, err := ib.GetMeta(ctx, accountID, srcID)
		if err != nil {
			return nil, nil, err
		}
		addBytes += uint64(meta.Size)
	}
	if err := ib.checkQuota(ctx, accountID, addBytes, uint32(len(emailIDs))); err != nil {
		return nil, nil, err
	}
	var newIDs, newIMAPUIDs []uint32
	err := ib.update(ctx, func(t *txn) error {
		newIDs = make([]uint32, 0, len(emailIDs))
		newIMAPUIDs = make([]uint32, 0, len(emailIDs))
		dest, err := t.mailbox(accountID, destMailboxID)
		if err != nil {
			return err
		}
		var bytes int64
		for _, srcID := range emailIDs {
			meta, err := t.meta(accountID, srcID)
			if err != nil {
				return err
			}
			bytes += int64(meta.Size)
			newID, err := t.nextEmailID(accountID)
			if err != nil {
				return err
			}
			uid, err := t.nextUID(accountID, &dest)
			if err != nil {
				return err
			}
			meta.MailboxID = destMailboxID
			meta.IMAPUID = uid
			meta.Flags &^= FlagRecent
			meta.ModSeq = nextModSeq(&dest)
			if err := t.putMeta(accountID, newID, meta); err != nil {
				return err
			}
			t.indexAdd(accountID, destMailboxID, newID)
			newIDs = append(newIDs, newID)
			newIMAPUIDs = append(newIMAPUIDs, uid)
		}
		if err := t.bumpCount(accountID, &dest, int32(len(emailIDs))); err != nil {
			return err
		}
		if err := t.putMailbox(accountID, dest); err != nil {
			return err
		}
		return t.addQuota(accountID, bytes, int32(len(emailIDs)))
	})
	if err != nil {
		return nil, nil, err
	}
	return newIDs, newIMAPUIDs, nil
}

// txnMailboxes loads each mailbox record once per txn and applies count deltas on save,
// so a count that passes through zero mid-operation is not rebuilt from the stale index.
type txnMailboxes struct {
	t         *txn
	accountID uint32
	boxes     map[uint32]*storage.Mailbox
	delta     map[uint32]int32
}

func newTxnMailboxes(t *txn, accountID uint32) *txnMailboxes {
	return &txnMailboxes{t: t, accountID: accountID, boxes: map[uint32]*storage.Mailbox{}, delta: map[uint32]int32{}}
}

func (b *txnMailboxes) get(id uint32) (*storage.Mailbox, error) {
	if m, ok := b.boxes[id]; ok {
		return m, nil
	}
	m, err := b.t.mailbox(b.accountID, id)
	if err != nil {
		return nil, err
	}
	b.boxes[id] = &m
	return &m, nil
}

func (b *txnMailboxes) save() error {
	for id, m := range b.boxes {
		if err := b.t.bumpCount(b.accountID, m, b.delta[id]); err != nil {
			return err
		}
		if err := b.t.putMailbox(b.accountID, *m); err != nil {
			return err
		}
	}
	return nil
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

// CreateMailbox adds a user folder and returns its record.
func (ib *Inbox) CreateMailbox(ctx context.Context, accountID uint32, name string) (Mailbox, error) {
	name = stringsTrimMailboxName(name)
	if err := ValidateMailboxName(name); err != nil {
		return Mailbox{}, err
	}
	var id uint32
	err := ib.update(ctx, func(t *txn) error {
		if _, err := ib.ResolveMailbox(ctx, accountID, name); err == nil {
			return ErrMailboxExists
		} else if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		var err error
		if id, err = ib.nextCustomMailboxID(ctx, accountID); err != nil {
			return err
		}
		// Reading the new key asserts it is still absent, so two concurrent creates cannot share id.
		if _, err := t.get(mailboxKey(accountID, id)); !errors.Is(err, storage.ErrNotFound) {
			if err == nil {
				err = storage.ErrCASConflict
			}
			return err
		}
		return t.putMailbox(accountID, storage.Mailbox{ID: id, Name: name, UIDNext: 1, UIDValidity: 1})
	})
	if err != nil {
		return Mailbox{}, err
	}
	return Mailbox{ID: id, Name: name, UIDValidity: 1, Subscribed: true}, nil
}

// DeleteMailbox removes an empty non-system folder.
func (ib *Inbox) DeleteMailbox(ctx context.Context, accountID, mailboxID uint32) error {
	if mailboxID <= DraftsMailboxID {
		return ErrSystemMailbox
	}
	return ib.update(ctx, func(t *txn) error {
		mbox, err := t.mailbox(accountID, mailboxID)
		if err != nil {
			return err
		}
		n := mbox.MessageCount
		if n == 0 {
			if n, err = ib.indexMessageCount(ctx, accountID, mailboxID); err != nil {
				return err
			}
		}
		if n > 0 {
			return ErrMailboxNotEmpty
		}
		t.del(mailboxKey(accountID, mailboxID))
		return nil
	})
}

// RenameMailbox renames a user folder and bumps UIDVALIDITY (RFC 3501).
func (ib *Inbox) RenameMailbox(ctx context.Context, accountID uint32, oldName, newName string) (Mailbox, error) {
	oldName = stringsTrimMailboxName(oldName)
	newName = stringsTrimMailboxName(newName)
	if err := ValidateMailboxName(oldName); err != nil {
		return Mailbox{}, err
	}
	if err := ValidateMailboxName(newName); err != nil {
		return Mailbox{}, err
	}
	if strings.EqualFold(oldName, "INBOX") {
		return Mailbox{}, ErrSystemMailbox
	}
	old, err := ib.ResolveMailbox(ctx, accountID, oldName)
	if err != nil {
		return Mailbox{}, err
	}
	if old.ID <= DraftsMailboxID {
		return Mailbox{}, ErrSystemMailbox
	}
	if _, err := ib.ResolveMailbox(ctx, accountID, newName); err == nil {
		return Mailbox{}, ErrMailboxExists
	} else if !errors.Is(err, storage.ErrNotFound) {
		return Mailbox{}, err
	}
	var rec storage.Mailbox
	err = ib.update(ctx, func(t *txn) error {
		var err error
		if rec, err = t.mailbox(accountID, old.ID); err != nil {
			return err
		}
		rec.Name = newName
		rec.UIDValidity++
		return t.putMailbox(accountID, rec)
	})
	if err != nil {
		return Mailbox{}, err
	}
	return Mailbox{ID: old.ID, Name: newName, UIDValidity: rec.UIDValidity}, nil
}

func (ib *Inbox) nextCustomMailboxID(ctx context.Context, accountID uint32) (uint32, error) {
	records, err := ib.listMailboxRecords(ctx, accountID)
	if err != nil {
		return 0, err
	}
	var max uint32 = DraftsMailboxID
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
