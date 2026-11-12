// Move and copy messages between mailboxes.
package mail

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/storage"
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
	err := ib.update(ctx, accountID, func(t *txn) error {
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
			meta.Flags |= FlagRecent // new in the destination (RFC 3501 6.4.7, RFC 6851)
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
	err := ib.update(ctx, accountID, func(t *txn) error {
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
			meta.Flags |= FlagRecent // new in the destination (RFC 3501 6.4.7, RFC 6851)
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

// CreateMailbox adds a user folder, plus any missing parent folders, and returns its record.
// subscribe sets their subscription; IMAP CREATE passes false (RFC 3501 does not subscribe), but a
// name still subscribed from a deleted folder gets its subscription back.
func (ib *Inbox) CreateMailbox(ctx context.Context, accountID uint32, name string, subscribe bool) (Mailbox, error) {
	// RFC 3501 §6.3.3: a trailing delimiter only declares the intent to create children.
	name = strings.TrimRight(stringsTrimMailboxName(name), "/")
	if err := ValidateMailboxName(name); err != nil {
		return Mailbox{}, err
	}
	if err := checkNewMailboxName(name); err != nil {
		return Mailbox{}, err
	}
	var id, uidValidity uint32
	var subscribed bool
	err := ib.update(ctx, accountID, func(t *txn) error {
		if _, err := ib.ResolveMailbox(t.ctx, accountID, name); err == nil {
			return ErrMailboxExists
		} else if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		records, err := ib.listMailboxRecords(t.ctx, accountID)
		if err != nil {
			return err
		}
		exists := make(map[string]bool, len(records))
		for _, m := range records {
			exists[MailboxKey(m.Name)] = true
		}
		// RFC 3501 §6.3.3: superior names the hierarchy needs are created with the folder.
		var names []string
		for i, c := range name {
			if c != '/' {
				continue
			}
			parent := name[:i]
			if parent != "" && !strings.HasSuffix(parent, "/") && !exists[MailboxKey(parent)] {
				names = append(names, parent)
			}
		}
		names = append(names, name)
		if len(records)+len(names) > MaxMailboxes {
			return ErrMailboxLimit
		}
		first, err := ib.nextCustomMailboxID(t.ctx, accountID)
		if err != nil {
			return err
		}
		orphans, err := t.orphanSubscriptions(accountID)
		if err != nil {
			return err
		}
		for i, n := range names {
			id = first + uint32(i)
			// Reading the new key asserts it is still absent, so two concurrent creates cannot share id.
			if _, err := t.get(mailboxKey(accountID, id)); !errors.Is(err, storage.ErrNotFound) {
				if err == nil {
					err = storage.ErrCASConflict
				}
				return err
			}
			if uidValidity, err = t.nextUIDValidity(accountID); err != nil {
				return err
			}
			subscribed = subscribe || slices.Contains(orphans, n)
			orphans = slices.DeleteFunc(orphans, func(o string) bool { return o == n })
			rec := storage.Mailbox{ID: id, Name: n, UIDNext: 1, UIDValidity: uidValidity, Subscribed: subscribed, SubSet: true}
			if err := t.putMailbox(accountID, rec); err != nil {
				return err
			}
		}
		return t.putOrphanSubscriptions(accountID, orphans)
	})
	if err != nil {
		return Mailbox{}, err
	}
	return Mailbox{ID: id, Name: name, UIDValidity: uidValidity, Subscribed: subscribed}, nil
}

// DeleteMailbox removes a non-system folder and its messages (RFC 3501 DELETE).
// ErrMailboxNotEmpty means a message arrived while it was being emptied.
func (ib *Inbox) DeleteMailbox(ctx context.Context, accountID, mailboxID uint32) error {
	if mailboxID <= DraftsMailboxID {
		return ErrSystemMailbox
	}
	ids, err := ib.ListMailboxIndexEmailIDs(ctx, accountID, mailboxID)
	if err != nil {
		return err
	}
	for _, id := range ids {
		// One message per transaction, as EXPUNGE does: blobs, index and quota stay consistent.
		if err := ib.DeleteMessage(ctx, accountID, id); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
	}
	return ib.update(ctx, accountID, func(t *txn) error {
		mbox, err := t.mailbox(accountID, mailboxID)
		if err != nil {
			return err
		}
		n := mbox.MessageCount
		if n == 0 {
			if n, err = ib.indexMessageCount(t.ctx, accountID, mailboxID); err != nil {
				return err
			}
		}
		if n > 0 {
			return ErrMailboxNotEmpty
		}
		t.del(mailboxKey(accountID, mailboxID))
		// An explicit subscription outlives the folder (RFC 3501 6.3.4).
		if !mbox.SubSet || !mbox.Subscribed {
			return nil
		}
		subs, err := t.orphanSubscriptions(accountID)
		if err != nil || slices.Contains(subs, mbox.Name) {
			return err
		}
		return t.putOrphanSubscriptions(accountID, append(subs, mbox.Name))
	})
}

// RenameMailbox renames a user folder together with every folder under it, and creates the
// superiors the new name needs (RFC 3501 6.3.5). Renaming INBOX moves its messages into a new
// folder and leaves INBOX, and the folders under it, in place. Each renamed folder gets a new
// UIDVALIDITY.
func (ib *Inbox) RenameMailbox(ctx context.Context, accountID uint32, oldName, newName string) (Mailbox, error) {
	if err := ValidateMailboxName(oldName); err != nil {
		return Mailbox{}, err
	}
	if err := ValidateMailboxName(newName); err != nil {
		return Mailbox{}, err
	}
	if err := checkNewMailboxName(newName); err != nil {
		return Mailbox{}, err
	}
	old, err := ib.ResolveMailbox(ctx, accountID, oldName)
	if err != nil {
		return Mailbox{}, err
	}
	if _, err := ib.ResolveMailbox(ctx, accountID, newName); err == nil {
		return Mailbox{}, ErrMailboxExists
	} else if !errors.Is(err, storage.ErrNotFound) {
		return Mailbox{}, err
	}
	if old.ID == InboxMailboxID {
		return ib.renameInbox(ctx, accountID, newName)
	}
	if old.ID <= DraftsMailboxID {
		return Mailbox{}, ErrSystemMailbox
	}
	oldKey, newKey := MailboxKey(old.Name), MailboxKey(newName)
	if strings.HasPrefix(newKey, oldKey+"/") {
		return Mailbox{}, ErrInvalidMailboxName // a folder cannot move under itself
	}
	// Superiors first, outside the rename: they are a SHOULD, and CreateMailbox applies the limits.
	if i := strings.LastIndexByte(newName, '/'); i > 0 {
		if _, err := ib.CreateMailbox(ctx, accountID, newName[:i], false); err != nil && !errors.Is(err, ErrMailboxExists) {
			return Mailbox{}, err
		}
	}
	var renamed storage.Mailbox
	err = ib.update(ctx, accountID, func(t *txn) error {
		records, err := ib.listMailboxRecords(t.ctx, accountID)
		if err != nil {
			return err
		}
		taken := make(map[string]bool, len(records))
		var moving []storage.Mailbox
		for _, m := range records {
			if k := MailboxKey(m.Name); k == oldKey || strings.HasPrefix(k, oldKey+"/") {
				moving = append(moving, m)
			} else {
				taken[k] = true
			}
		}
		for _, m := range moving {
			m.Name = newName + m.Name[len(old.Name):]
			if err := checkNewMailboxName(m.Name); err != nil {
				return err
			}
			if taken[MailboxKey(m.Name)] {
				return ErrMailboxExists
			}
			if m.UIDValidity, err = t.nextUIDValidity(accountID); err != nil {
				return err
			}
			if err := t.putMailbox(accountID, m); err != nil {
				return err
			}
			if m.ID == old.ID {
				renamed = m
			}
		}
		return nil
	})
	if err != nil {
		return Mailbox{}, err
	}
	return Mailbox{ID: old.ID, Name: newName, UIDValidity: renamed.UIDValidity}, nil
}

// renameInbox is RENAME INBOX (RFC 3501 6.3.5): a new folder takes all of INBOX's messages; INBOX
// stays, empty, and keeps the folders under it.
func (ib *Inbox) renameInbox(ctx context.Context, accountID uint32, newName string) (Mailbox, error) {
	dest, err := ib.CreateMailbox(ctx, accountID, newName, false)
	if err != nil {
		return Mailbox{}, err
	}
	msgs, err := ib.List(ctx, accountID, InboxMailboxID)
	if err != nil {
		return Mailbox{}, err
	}
	ids := make([]uint32, len(msgs))
	for i, m := range msgs {
		ids[i] = m.StorageID()
	}
	if _, err := ib.MoveMessages(ctx, accountID, ids, dest.ID); err != nil {
		return Mailbox{}, err
	}
	return dest, nil
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

// stringsTrimMailboxName is the name as given: IMAP passes it parsed, and leading or trailing
// spaces are part of a name (RFC 3501 5.1), so " dup" and "dup" are two folders.
func stringsTrimMailboxName(name string) string { return name }
