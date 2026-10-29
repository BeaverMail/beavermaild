// Optimistic read-modify-write transactions for mailbox records, counters and message rows.
package mail

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// txnAttempts bounds reruns of one update under write contention.
const txnAttempts = 100

// errTxnContention is returned when an update keeps losing its CAS checks.
var errTxnContention = errors.New("mail: too much write contention")

// txn collects the reads and writes of one update. Every row read through get is asserted
// unchanged at commit, so a concurrent writer (goroutine or another process on the same store)
// makes the commit fail and the update rerun instead of overwriting the other writer.
type txn struct {
	ctx        context.Context
	ib         *Inbox
	read       map[string][]byte // value at first read; nil = absent
	readOrder  []string
	write      map[string][]byte // pending value; nil = delete
	writeOrder []string
}

// update runs fn in a txn and commits its writes in one batch, rerunning fn on CAS conflict.
// fn must not have side effects outside the txn, as it may run several times.
func (ib *Inbox) update(ctx context.Context, fn func(t *txn) error) error {
	for attempt := range txnAttempts {
		t := &txn{ctx: ctx, ib: ib, read: map[string][]byte{}, write: map[string][]byte{}}
		if err := fn(t); err != nil {
			return err
		}
		if len(t.writeOrder) == 0 {
			return nil
		}
		batch := storage.NewBatch()
		for _, k := range t.readOrder {
			if err := batch.AssertRaw([]byte(k), t.read[k]); err != nil {
				return err
			}
		}
		for _, k := range t.writeOrder {
			var err error
			if v := t.write[k]; v == nil {
				err = batch.DeleteRaw([]byte(k))
			} else {
				err = batch.SetRaw([]byte(k), v)
			}
			if err != nil {
				return err
			}
		}
		err := ib.store.Commit(ctx, batch)
		if !errors.Is(err, storage.ErrCASConflict) {
			return err
		}
		time.Sleep(time.Duration(1+rand.IntN(attempt+1)) * time.Millisecond)
	}
	return errTxnContention
}

// get returns the value for key as seen by this txn (its own writes first).
func (t *txn) get(key []byte) ([]byte, error) {
	k := string(key)
	if v, ok := t.write[k]; ok {
		if v == nil {
			return nil, storage.ErrNotFound
		}
		return v, nil
	}
	v, ok := t.read[k]
	if !ok {
		var err error
		v, err = t.ib.store.Get(t.ctx, key)
		if errors.Is(err, storage.ErrNotFound) {
			v = nil
		} else if err != nil {
			return nil, err
		} else if v == nil {
			v = []byte{}
		}
		t.read[k] = v
		t.readOrder = append(t.readOrder, k)
	}
	if v == nil {
		return nil, storage.ErrNotFound
	}
	return v, nil
}

func (t *txn) set(key, value []byte) {
	k := string(key)
	if _, ok := t.write[k]; !ok {
		t.writeOrder = append(t.writeOrder, k)
	}
	t.write[k] = value
}

func (t *txn) del(key []byte) {
	k := string(key)
	if _, ok := t.write[k]; !ok {
		t.writeOrder = append(t.writeOrder, k)
	}
	t.write[k] = nil
}

func (t *txn) getPersist(key []byte, v any) error {
	wire, err := t.get(key)
	if err != nil {
		return err
	}
	return storage.UnmarshalPersist(wire, v)
}

func (t *txn) setPersist(key []byte, v any) error {
	wire, err := storage.MarshalPersist(nil, 1, v)
	if err != nil {
		return err
	}
	t.set(key, wire)
	return nil
}

func mailboxKey(accountID, mailboxID uint32) []byte {
	return storage.AppendKey(nil, storage.SubspaceMail, accountID, mailboxID, byte(storage.CollectionMailbox), nil)
}

func emailKey(accountID, emailID uint32) []byte {
	return storage.AppendKey(nil, storage.SubspaceMail, accountID, emailID, byte(storage.CollectionEmail), nil)
}

func emailCounterKey(accountID uint32) []byte {
	return storage.AppendKey(nil, storage.SubspaceLookup, 0, 0, 0, fmt.Appendf(nil, "meta/email/%d", accountID))
}

func (t *txn) mailbox(accountID, mailboxID uint32) (storage.Mailbox, error) {
	var mbox storage.Mailbox
	err := t.getPersist(mailboxKey(accountID, mailboxID), &mbox)
	return mbox, err
}

func (t *txn) putMailbox(accountID uint32, mbox storage.Mailbox) error {
	return t.setPersist(mailboxKey(accountID, mbox.ID), mbox)
}

func (t *txn) meta(accountID, emailID uint32) (storage.EmailMeta, error) {
	var meta storage.EmailMeta
	err := t.getPersist(emailKey(accountID, emailID), &meta)
	return meta, err
}

func (t *txn) putMeta(accountID, emailID uint32, meta storage.EmailMeta) error {
	return t.setPersist(emailKey(accountID, emailID), meta)
}

func (t *txn) indexAdd(accountID, mailboxID, emailID uint32) {
	if emailID != storage.MailboxIndexSentinelEmailID {
		t.set(storage.AppendMailboxIndexKey(nil, accountID, mailboxID, emailID), storage.MailboxIndexEntryValue)
	}
	t.set(storage.AppendMailboxIndexKey(nil, accountID, mailboxID, storage.MailboxIndexSentinelEmailID), storage.MailboxIndexEntryValue)
}

func (t *txn) indexRemove(accountID, mailboxID, emailID uint32) {
	if emailID != storage.MailboxIndexSentinelEmailID {
		t.del(storage.AppendMailboxIndexKey(nil, accountID, mailboxID, emailID))
	}
}

// nextEmailID allocates the next email document id for accountID.
func (t *txn) nextEmailID(accountID uint32) (uint32, error) {
	key := emailCounterKey(accountID)
	var next uint32
	if err := t.getPersist(key, &next); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return 0, err
	}
	next++
	return next, t.setPersist(key, next)
}

// nextUID allocates the next IMAP UID on mbox; the caller saves mbox.
func (t *txn) nextUID(accountID uint32, mbox *storage.Mailbox) (uint32, error) {
	if err := t.initUIDs(accountID, mbox); err != nil {
		return 0, err
	}
	uid := mbox.UIDNext
	if uid == 0 {
		uid = 1
	}
	mbox.UIDNext = uid + 1
	return uid, nil
}

// nextModSeq allocates the next MODSEQ on mbox; the caller saves mbox.
func nextModSeq(mbox *storage.Mailbox) uint64 {
	mbox.HighestModSeq++
	if mbox.HighestModSeq == 0 {
		mbox.HighestModSeq = 1
	}
	return mbox.HighestModSeq
}

// initUIDs assigns legacy IMAPUID=emailID and sets UIDNext once per mailbox; the caller saves mbox.
// shortcut: the legacy rows come from a scan, not asserted; only pre-UID stores take this path.
func (t *txn) initUIDs(accountID uint32, mbox *storage.Mailbox) error {
	if mbox.UIDSeqInit {
		return nil
	}
	msgs, err := t.ib.listAccountEmailsInMailbox(t.ctx, accountID, mbox.ID)
	if err != nil {
		return err
	}
	var maxUID uint32
	for _, m := range msgs {
		meta := m.Meta
		if meta.IMAPUID == 0 {
			meta.IMAPUID = m.EmailID
			if err := t.putMeta(accountID, m.EmailID, meta); err != nil {
				return err
			}
		}
		maxUID = max(maxUID, meta.IMAPUID)
	}
	mbox.UIDNext = max(mbox.UIDNext, maxUID+1, 1)
	mbox.UIDSeqInit = true
	return nil
}

// bumpCount adjusts mbox.MessageCount by delta; the caller saves mbox.
// A zero count may be an unsynced legacy record, so it is rebuilt from the committed index first.
func (t *txn) bumpCount(accountID uint32, mbox *storage.Mailbox, delta int32) error {
	n := int64(mbox.MessageCount)
	if n == 0 {
		c, err := t.ib.indexMessageCount(t.ctx, accountID, mbox.ID)
		if err != nil {
			return err
		}
		n = int64(c)
	}
	mbox.MessageCount = uint32(max(n+int64(delta), 0))
	return nil
}

// addQuota adjusts the usage counters of accountID by the given deltas.
func (t *txn) addQuota(accountID uint32, bytes int64, messages int32) error {
	key := t.ib.quotaLookupKey(accountID)
	var rec quotaRecord
	err := t.getPersist(key, &rec)
	if errors.Is(err, storage.ErrNotFound) {
		rec, err = t.ib.newQuotaRecord(t.ctx, accountID)
	}
	if err != nil {
		return err
	}
	rec.StorageUsed = uint64(max(int64(rec.StorageUsed)+bytes, 0))
	rec.MessagesUsed = uint32(max(int64(rec.MessagesUsed)+int64(messages), 0))
	return t.setPersist(key, rec)
}
