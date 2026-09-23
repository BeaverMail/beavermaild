// Outbound mail queue in SubspaceQueue (blob payload + recipient list).
package mail

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
)

const (
	queueAccountID     uint32 = 0
	queueMsgCollection byte   = 1

	rcptDelivered     uint64 = 1 << 0
	rcptPermanentFail uint64 = 1 << 1

	// queueHeld marks a message paused by an admin (worker skips until Unhold).
	queueHeld uint64 = 1 << 0
)

// QueueEntry is one pending outbound message.
type QueueEntry struct {
	ID  uint32
	Msg storage.QueueMessage
}

// Queue stores outbound SMTP jobs.
type Queue struct {
	store storage.Store
	blobs *blob.FS
}

// NewQueue returns an outbound queue over store and blobs.
func NewQueue(store storage.Store, blobs *blob.FS) *Queue {
	return &Queue{store: store, blobs: blobs}
}

// Enqueue stores raw message bytes for delivery to recipients (default DSN notify flags).
func (q *Queue) Enqueue(ctx context.Context, returnPath string, recipients []string, raw []byte) (uint32, error) {
	env := EnvelopeDSN{
		ReturnPath: returnPath,
		Ret:        RetNone,
	}
	for _, addr := range recipients {
		env.Recipients = append(env.Recipients, RcptDSN{
			Address: addr,
			Notify:  NotifyDefault,
		})
	}
	return q.EnqueueDSN(ctx, env, raw)
}

// EnqueueDSN stores a message with MAIL/RCPT DSN parameters.
func (q *Queue) EnqueueDSN(ctx context.Context, env EnvelopeDSN, raw []byte) (uint32, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("mail: empty message")
	}
	if len(env.Recipients) == 0 {
		return 0, fmt.Errorf("mail: no recipients")
	}

	hash, err := q.blobs.Put(ctx, raw)
	if err != nil {
		return 0, err
	}

	id, err := q.nextQueueID(ctx)
	if err != nil {
		return 0, err
	}

	rcpts := make([]storage.QueueRecipient, len(env.Recipients))
	for i, r := range env.Recipients {
		notify := r.Notify
		if notify == 0 {
			notify = NotifyDefault
		}
		rcpts[i] = storage.QueueRecipient{
			Address: strings.ToLower(strings.TrimSpace(r.Address)),
			Notify:  NotifyToStorage(notify),
			Orcpt:   r.Orcpt,
		}
	}
	msg := storage.QueueMessage{
		Created:    uint64(time.Now().Unix()),
		BlobHash:   hash,
		ReturnPath: strings.ToLower(strings.TrimSpace(env.ReturnPath)),
		Recipients: rcpts,
		Size:       uint64(len(raw)),
		Ret:        string(env.Ret),
		Envid:      env.Envid,
		Body:       env.Body,
	}
	wire, err := storage.MarshalPersist(nil, 1, msg)
	if err != nil {
		return 0, err
	}

	batch := storage.NewBatch().WithAccount(queueAccountID)
	suffix := storage.BatchSuffix(queueMsgCollection, id, nil)
	if err := batch.Set(storage.SubspaceQueue, suffix, wire); err != nil {
		return 0, err
	}
	if err := q.store.Commit(ctx, batch); err != nil {
		return 0, err
	}
	return id, nil
}

// ListPending returns all queue entries with at least one undelivered recipient.
func (q *Queue) ListPending(ctx context.Context) ([]QueueEntry, error) {
	return q.list(ctx, true)
}

// ListAll returns every queue entry still stored.
func (q *Queue) ListAll(ctx context.Context) ([]QueueEntry, error) {
	return q.list(ctx, false)
}

// Get loads one queue entry by id.
func (q *Queue) Get(ctx context.Context, id uint32) (QueueEntry, error) {
	key := storage.AppendKey(nil, storage.SubspaceQueue, queueAccountID, id, queueMsgCollection, nil)
	wire, err := q.store.Get(ctx, key)
	if err != nil {
		return QueueEntry{}, err
	}
	var msg storage.QueueMessage
	if err := storage.UnmarshalPersist(wire, &msg); err != nil {
		return QueueEntry{}, err
	}
	return QueueEntry{ID: id, Msg: msg}, nil
}

// IsHeld reports whether the message is admin-held.
func IsHeld(msg storage.QueueMessage) bool {
	return msg.Flags&queueHeld != 0
}

// Hold pauses delivery attempts for the entry until Unhold.
func (q *Queue) Hold(ctx context.Context, id uint32) error {
	e, err := q.Get(ctx, id)
	if err != nil {
		return err
	}
	if IsHeld(e.Msg) {
		return nil
	}
	e.Msg.Flags |= queueHeld
	return q.Save(ctx, id, e.Msg)
}

// Unhold resumes delivery for a held entry.
func (q *Queue) Unhold(ctx context.Context, id uint32) error {
	e, err := q.Get(ctx, id)
	if err != nil {
		return err
	}
	if !IsHeld(e.Msg) {
		return nil
	}
	e.Msg.Flags &^= queueHeld
	return q.Save(ctx, id, e.Msg)
}

// RetryNow sets NextDue=0 for pending recipients (optional address filter) and clears hold.
func (q *Queue) RetryNow(ctx context.Context, id uint32, address string) error {
	e, err := q.Get(ctx, id)
	if err != nil {
		return err
	}
	address = strings.ToLower(strings.TrimSpace(address))
	matched := 0
	e.Msg.Flags &^= queueHeld
	for i := range e.Msg.Recipients {
		rcpt := &e.Msg.Recipients[i]
		if !recipientPending(*rcpt) {
			continue
		}
		if address != "" && rcpt.Address != address {
			continue
		}
		rcpt.NextDue = 0
		matched++
	}
	if matched == 0 {
		if address != "" {
			return fmt.Errorf("mail: no pending recipient %q: %w", address, storage.ErrNotFound)
		}
		return fmt.Errorf("mail: no pending recipients: %w", storage.ErrNotFound)
	}
	return q.Save(ctx, id, e.Msg)
}

// Cancel removes the queue entry without sending a DSN (admin discard).
func (q *Queue) Cancel(ctx context.Context, id uint32) error {
	if _, err := q.Get(ctx, id); err != nil {
		return err
	}
	return q.Delete(ctx, id)
}

// RecipientStatus returns pending, delivered, or failed for one queue recipient.
func RecipientStatus(rcpt storage.QueueRecipient) string {
	if rcpt.Flags&rcptDelivered != 0 {
		return "delivered"
	}
	if rcpt.Flags&rcptPermanentFail != 0 {
		return "failed"
	}
	return "pending"
}

func (q *Queue) list(ctx context.Context, pendingOnly bool) ([]QueueEntry, error) {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceQueue, queueAccountID, 0, queueMsgCollection, 6)
	to := storage.AppendKey(nil, storage.SubspaceQueue, queueAccountID, ^uint32(0), queueMsgCollection, nil)

	var out []QueueEntry
	err := q.store.Iterate(ctx, from, to, func(k, v []byte) error {
		parts, err := storage.DecodeKey(k)
		if err != nil {
			return err
		}
		if parts.Collection != queueMsgCollection || len(parts.Suffix) > 0 {
			return nil
		}
		var msg storage.QueueMessage
		if err := storage.UnmarshalPersist(v, &msg); err != nil {
			return err
		}
		if pendingOnly && pendingRecipients(msg) == 0 {
			return nil
		}
		out = append(out, QueueEntry{ID: parts.DocumentID, Msg: msg})
		return nil
	})
	slices.SortFunc(out, func(a, b QueueEntry) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return out, err
}

// Save updates a queue entry.
func (q *Queue) Save(ctx context.Context, id uint32, msg storage.QueueMessage) error {
	wire, err := storage.MarshalPersist(nil, 1, msg)
	if err != nil {
		return err
	}
	batch := storage.NewBatch().WithAccount(queueAccountID)
	suffix := storage.BatchSuffix(queueMsgCollection, id, nil)
	if err := batch.Set(storage.SubspaceQueue, suffix, wire); err != nil {
		return err
	}
	return q.store.Commit(ctx, batch)
}

// Delete removes a queue entry.
func (q *Queue) Delete(ctx context.Context, id uint32) error {
	batch := storage.NewBatch().WithAccount(queueAccountID)
	suffix := storage.BatchSuffix(queueMsgCollection, id, nil)
	if err := batch.Delete(storage.SubspaceQueue, suffix); err != nil {
		return err
	}
	return q.store.Commit(ctx, batch)
}

// LoadRaw returns RFC 5322 bytes for a queue message.
func (q *Queue) LoadRaw(ctx context.Context, msg storage.QueueMessage) ([]byte, error) {
	if !msg.HasBlob() {
		return nil, storage.ErrNotFound
	}
	return q.blobs.Get(ctx, msg.BlobHash)
}

func (q *Queue) nextQueueID(ctx context.Context) (uint32, error) {
	key := storage.AppendKey(nil, storage.SubspaceLookup, 0, 0, 0, []byte("meta/queue"))
	wire, err := q.store.Get(ctx, key)
	var next uint32 = 1
	if err == nil {
		if err := storage.UnmarshalPersist(wire, &next); err != nil {
			return 0, err
		}
		next++
	} else if !errors.Is(err, storage.ErrNotFound) {
		return 0, err
	}

	encoded, err := storage.MarshalPersist(nil, 1, next)
	if err != nil {
		return 0, err
	}
	batch := storage.NewBatch().WithAccount(0)
	suffix := storage.BatchSuffix(0, 0, []byte("meta/queue"))
	if err := batch.Set(storage.SubspaceLookup, suffix, encoded); err != nil {
		return 0, err
	}
	if err := q.store.Commit(ctx, batch); err != nil {
		return 0, err
	}
	return next, nil
}

func pendingRecipients(msg storage.QueueMessage) int {
	n := 0
	for _, rcpt := range msg.Recipients {
		if recipientPending(rcpt) {
			n++
		}
	}
	return n
}

func recipientPending(rcpt storage.QueueRecipient) bool {
	return rcpt.Flags&rcptDelivered == 0 && rcpt.Flags&rcptPermanentFail == 0
}

// MarkDelivered sets the delivered flag on recipient i.
func MarkDelivered(msg *storage.QueueMessage, i int) {
	msg.Recipients[i].Flags |= rcptDelivered
}

// MarkPermanentFail marks recipient i as permanently undeliverable.
func MarkPermanentFail(msg *storage.QueueMessage, i int) {
	msg.Recipients[i].Flags |= rcptPermanentFail
}

// RecordAttempt stores the last delivery attempt time on recipient i.
func RecordAttempt(msg *storage.QueueMessage, i int, now time.Time) {
	msg.Recipients[i].LastAttempt = now.UnixMilli()
}

// ScheduleNextRetry sets the next attempt time after a transient failure.
func ScheduleNextRetry(msg *storage.QueueMessage, i int, policy QueuePolicy, now time.Time) {
	attempt := msg.Recipients[i].Retry
	msg.Recipients[i].NextDue = policy.NextDueAfterFailure(attempt, now).UnixMilli()
	msg.Recipients[i].Retry++
}

// AllDone reports whether every recipient is delivered, permanent fail, or expired handling done.
func AllDone(msg storage.QueueMessage) bool {
	for _, rcpt := range msg.Recipients {
		if recipientPending(rcpt) {
			return false
		}
	}
	return true
}
