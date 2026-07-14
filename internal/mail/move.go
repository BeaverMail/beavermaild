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
	if _, err := ib.mailboxRecord(ctx, accountID, destMailboxID); err != nil {
		return nil, err
	}
	batch := storage.NewBatch().WithAccount(accountID)
	destUIDs := make([]uint32, 0, len(emailIDs))
	for _, id := range emailIDs {
		meta, err := ib.GetMeta(ctx, accountID, id)
		if err != nil {
			return nil, err
		}
		srcMailbox := meta.MailboxID
		imapUID, err := ib.allocateIMAPUID(ctx, accountID, destMailboxID)
		if err != nil {
			return nil, err
		}
		meta.MailboxID = destMailboxID
		meta.IMAPUID = imapUID
		meta.Flags &^= FlagRecent
		modSeq, err := ib.allocateModSeq(ctx, accountID, destMailboxID)
		if err != nil {
			return nil, err
		}
		meta.ModSeq = modSeq
		wire, err := storage.MarshalPersist(nil, 1, meta)
		if err != nil {
			return nil, err
		}
		suffix := storage.DocumentSuffix(storage.CollectionEmail, id, nil)
		if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
			return nil, err
		}
		if err := ib.queueMailboxIndexRemove(batch, srcMailbox, id); err != nil {
			return nil, err
		}
		if err := ib.queueMailboxIndexAdd(batch, destMailboxID, id); err != nil {
			return nil, err
		}
		if err := ib.queueMailboxIndexReady(batch, destMailboxID); err != nil {
			return nil, err
		}
		destUIDs = append(destUIDs, imapUID)
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
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
	var addMsgs uint32
	metas := make([]storage.EmailMeta, 0, len(emailIDs))
	for _, srcID := range emailIDs {
		meta, err := ib.GetMeta(ctx, accountID, srcID)
		if err != nil {
			return nil, nil, err
		}
		metas = append(metas, meta)
		addBytes += uint64(meta.Size)
		addMsgs++
	}
	if err := ib.checkQuota(ctx, accountID, addBytes, addMsgs); err != nil {
		return nil, nil, err
	}
	var newIDs, newIMAPUIDs []uint32
	batch := storage.NewBatch().WithAccount(accountID)
	for i := range emailIDs {
		meta := metas[i]
		newID, err := ib.nextEmailID(ctx, accountID)
		if err != nil {
			return nil, nil, err
		}
		imapUID, err := ib.allocateIMAPUID(ctx, accountID, destMailboxID)
		if err != nil {
			return nil, nil, err
		}
		meta.MailboxID = destMailboxID
		meta.IMAPUID = imapUID
		meta.Flags &^= FlagRecent
		modSeq, err := ib.allocateModSeq(ctx, accountID, destMailboxID)
		if err != nil {
			return nil, nil, err
		}
		meta.ModSeq = modSeq
		wire, err := storage.MarshalPersist(nil, 1, meta)
		if err != nil {
			return nil, nil, err
		}
		suffix := storage.DocumentSuffix(storage.CollectionEmail, newID, nil)
		if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
			return nil, nil, err
		}
		if err := ib.queueMailboxIndexAdd(batch, destMailboxID, newID); err != nil {
			return nil, nil, err
		}
		if err := ib.queueMailboxIndexReady(batch, destMailboxID); err != nil {
			return nil, nil, err
		}
		newIDs = append(newIDs, newID)
		newIMAPUIDs = append(newIMAPUIDs, imapUID)
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
		return nil, nil, err
	}
	if err := ib.addQuotaUsage(ctx, accountID, addBytes, addMsgs); err != nil {
		return nil, nil, err
	}
	return newIDs, newIMAPUIDs, nil
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
	return Mailbox{ID: id, Name: name, UIDValidity: 1, Subscribed: true}, nil
}

// DeleteMailbox removes an empty non-system folder.
func (ib *Inbox) DeleteMailbox(ctx context.Context, accountID, mailboxID uint32) error {
	if mailboxID <= DraftsMailboxID {
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
	rec, err := ib.mailboxRecord(ctx, accountID, old.ID)
	if err != nil {
		return Mailbox{}, err
	}
	rec.Name = newName
	rec.UIDValidity++
	wire, err := storage.MarshalPersist(nil, 1, rec)
	if err != nil {
		return Mailbox{}, err
	}
	batch := storage.NewBatch().WithAccount(accountID)
	suffix := storage.DocumentSuffix(storage.CollectionMailbox, old.ID, nil)
	if err := batch.Set(storage.SubspaceMail, suffix, wire); err != nil {
		return Mailbox{}, err
	}
	if err := ib.store.Commit(ctx, batch); err != nil {
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
