// Background worker that drains the outbound mail queue.
package mail

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
)

// RemoteDeliverer submits mail to remote recipients (relay or MX).
type RemoteDeliverer interface {
	DeliverRemote(ctx context.Context, mailFrom, rcptTo string, data []byte) error
}

// Worker delivers queued messages locally or via RemoteDeliverer.
type Worker struct {
	log    *slog.Logger
	queue  *Queue
	inbox  *Inbox
	dir    *directory.Local
	remote RemoteDeliverer
	policy QueuePolicy
}

// NewWorker returns a queue worker. remote may be nil when only local delivery is needed.
func NewWorker(log *slog.Logger, queue *Queue, inbox *Inbox, dir *directory.Local, remote RemoteDeliverer, policy QueuePolicy) *Worker {
	if policy.RunDelay == 0 {
		policy = DefaultQueuePolicy()
	}
	return &Worker{
		log:    log,
		queue:  queue,
		inbox:  inbox,
		dir:    dir,
		remote: remote,
		policy: policy,
	}
}

// Run polls the queue until ctx is canceled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.policy.RunDelay)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.drain(ctx)
		}
	}
}

// ProcessOnce drains pending queue entries once (for tests).
func (w *Worker) ProcessOnce(ctx context.Context) {
	w.drain(ctx)
}

func (w *Worker) drain(ctx context.Context) {
	entries, err := w.queue.ListPending(ctx)
	if err != nil {
		w.log.Warn("queue list", slog.Any("err", err))
		return
	}
	for _, e := range entries {
		if err := w.deliverEntry(ctx, e); err != nil && ctx.Err() == nil {
			w.log.Warn("queue deliver", "id", e.ID, slog.Any("err", err))
		}
	}
}

func (w *Worker) deliverEntry(ctx context.Context, e QueueEntry) error {
	msg := e.Msg
	if pendingRecipients(msg) == 0 {
		return w.queue.Delete(ctx, e.ID)
	}

	created := time.Unix(int64(msg.Created), 0)
	now := time.Now()
	if w.policy.Expired(created, now) {
		return w.expireEntry(ctx, e)
	}

	raw, err := w.queue.LoadRaw(ctx, msg)
	if err != nil {
		return err
	}

	changed := false
	for i := range msg.Recipients {
		rcpt := &msg.Recipients[i]
		if !recipientPending(*rcpt) {
			continue
		}
		if !w.policy.ReadyForAttempt(rcpt.NextDue, now) {
			continue
		}
		RecordAttempt(&msg, i, now)
		if err := w.deliverTo(ctx, msg.ReturnPath, rcpt.Address, raw); err != nil {
			w.log.Debug("queue rcpt failed", "rcpt", rcpt.Address, slog.Any("err", err))
			if deliveryPermanent(err) {
				MarkPermanentFail(&msg, i)
			} else {
				ScheduleNextRetry(&msg, i, w.policy, now)
			}
			changed = true
			continue
		}
		MarkDelivered(&msg, i)
		changed = true
	}

	if !changed {
		return nil
	}
	if AllDone(msg) {
		return w.queue.Delete(ctx, e.ID)
	}
	return w.queue.Save(ctx, e.ID, msg)
}

// expireEntry notifies return-path for pending recipients and removes the queue entry.
func (w *Worker) expireEntry(ctx context.Context, e QueueEntry) error {
	msg := e.Msg
	w.log.Info("queue message expired", "id", e.ID, "return_path", msg.ReturnPath)
	returnPath := strings.TrimSpace(msg.ReturnPath)
	for _, rcpt := range msg.Recipients {
		if !recipientPending(rcpt) || returnPath == "" {
			continue
		}
		bounce := BuildExpireBounce(returnPath, rcpt.Address, e.ID)
		if err := w.deliverTo(ctx, "", returnPath, bounce); err != nil {
			w.log.Warn("bounce deliver failed", "return_path", returnPath, slog.Any("err", err))
		}
	}
	return w.queue.Delete(ctx, e.ID)
}

func (w *Worker) deliverTo(ctx context.Context, returnPath, rcpt string, raw []byte) error {
	acc, _, err := w.dir.ResolveEmail(ctx, rcpt)
	if err == nil {
		if !acc.Active {
			return directory.ErrInactive
		}
		_, err = w.inbox.Deliver(ctx, acc.ID, raw)
		return err
	}
	if !errors.Is(err, directory.ErrNotFound) {
		return err
	}
	if w.remote == nil {
		return errors.New("mail: no remote delivery configured")
	}
	return w.remote.DeliverRemote(ctx, returnPath, rcpt, raw)
}

func deliveryPermanent(err error) bool {
	type permanent interface {
		error
		DeliveryPermanent() bool
	}
	var p permanent
	if errors.As(err, &p) {
		return p.DeliveryPermanent()
	}
	return errors.Is(err, directory.ErrInactive)
}
