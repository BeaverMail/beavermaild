// Optimistic read-modify-write transactions for mailbox records, counters and message rows.
package mail

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// txnAttempts bounds reruns of one update under write contention.
const txnAttempts = 100

// ErrContention is returned when an update keeps losing its CAS checks; the caller may retry.
var ErrContention = errors.New("mail: too much write contention")

// accountLockWait bounds the wait for another writer of the same account. Past it the update runs
// unlocked, still safe through CAS: a nesting the reentrancy check misses costs a delay, never a deadlock.
const accountLockWait = 5 * time.Second

// accountLocks serializes the updates of one account in this process. Optimistic CAS alone lets a
// transaction with several hot rows (APPEND: mailbox, email counter, quota) lose every retry to
// smaller ones; queueing them leaves CAS only the conflicts with other processes.
var accountLocks sync.Map // accountLockKey -> chan struct{} (capacity 1)

type accountLockKey struct {
	store   storage.Store
	account uint32
}

type heldLockKey struct{}

// slowLockHold is the lock hold time past which an update is logged.
const slowLockHold = 250 * time.Millisecond

// lockCaller names the function that started the update (the caller of Inbox.update).
func lockCaller() string {
	pcs := make([]uintptr, 8)
	n := runtime.Callers(4, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if !strings.HasSuffix(f.Function, ".update") && !strings.Contains(f.Function, "lockAccount") {
			return fmt.Sprintf("%s:%d", f.Function, f.Line)
		}
		if !more {
			return ""
		}
	}
}

// lockAccount takes the account's write lock unless ctx already holds it (a nested update). It
// returns the context to pass to nested calls and the release function.
func (ib *Inbox) lockAccount(ctx context.Context, accountID uint32) (context.Context, func()) {
	key := accountLockKey{ib.store, accountID}
	if held, _ := ctx.Value(heldLockKey{}).(accountLockKey); held == key {
		return ctx, func() {}
	}
	v, _ := accountLocks.LoadOrStore(key, make(chan struct{}, 1))
	ch := v.(chan struct{})
	timer := time.NewTimer(accountLockWait)
	defer timer.Stop()
	start := time.Now()
	select {
	case ch <- struct{}{}:
		taken := time.Now()
		return context.WithValue(ctx, heldLockKey{}, key), func() {
			<-ch
			if held := time.Since(taken); held > slowLockHold {
				ib.logger().Warn("mail write lock held long", "account", accountID, "held", held, "waited", taken.Sub(start), "caller", lockCaller())
			}
		}
	case <-timer.C:
		// A nested update called without the outer t.ctx waits for itself until here.
		ib.logger().Warn("mail write lock wait timed out, running unlocked", "account", accountID, "stack", string(debug.Stack()))
		return ctx, func() {}
	case <-ctx.Done():
		return ctx, func() {}
	}
}

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
// fn must not have side effects outside the txn, as it may run several times. Updates of the same
// account run one at a time; fn must pass t.ctx to any nested update so it does not wait for itself.
func (ib *Inbox) update(ctx context.Context, accountID uint32, fn func(t *txn) error) error {
	ctx, unlock := ib.lockAccount(ctx, accountID)
	defer unlock()
	return ib.updateOptimistic(ctx, fn)
}

// updateOptimistic is update without the account write lock, CAS only. For small transactions
// many sessions run at once where only one can change anything (claiming \Recent): queueing them
// on the lock made all wait for the one; here the losers rerun, see nothing left, and stop.
func (ib *Inbox) updateOptimistic(ctx context.Context, fn func(t *txn) error) error {
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
	return ErrContention
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

func uidValidityCounterKey(accountID uint32) []byte {
	return storage.AppendKey(nil, storage.SubspaceLookup, 0, 0, 0, fmt.Appendf(nil, "meta/uidvalidity/%d", accountID))
}

// nextUIDValidity allocates a UIDVALIDITY for a new mailbox: never reused within the account, so a
// mailbox deleted and created again (which may get the same id) never repeats its old value. It starts
// from the clock, as Dovecot does, so it also stays above the values of mailboxes created before it.
func (t *txn) nextUIDValidity(accountID uint32) (uint32, error) {
	key := uidValidityCounterKey(accountID)
	var last uint32
	if err := t.getPersist(key, &last); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return 0, err
	}
	next := max(last+1, uint32(time.Now().Unix()))
	return next, t.setPersist(key, next)
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
