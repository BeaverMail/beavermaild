// Background worker that drains the outbound mail queue.
package mail

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/storage"
)

// RemoteDeliverer submits mail to remote recipients (relay or MX).
type RemoteDeliverer interface {
	DeliverRemote(ctx context.Context, mailFrom, rcptTo string, data []byte) error
}

// OutboundSigner adds DKIM signatures before remote delivery.
type OutboundSigner interface {
	Sign(returnPath string, raw []byte) ([]byte, error)
}

// Worker delivers queued messages locally or via RemoteDeliverer.
type Worker struct {
	log    *slog.Logger
	queue  *Queue
	inbox  *Inbox
	dir    *directory.Local
	remote RemoteDeliverer
	signer OutboundSigner
	policy QueuePolicy
}

// NewWorker returns a queue worker. remote may be nil when only local delivery is needed.
func NewWorker(log *slog.Logger, queue *Queue, inbox *Inbox, dir *directory.Local, remote RemoteDeliverer, signer OutboundSigner, policy QueuePolicy) *Worker {
	if policy.RunDelay == 0 {
		policy = DefaultQueuePolicy()
	}
	return &Worker{
		log:    log,
		queue:  queue,
		inbox:  inbox,
		dir:    dir,
		remote: remote,
		signer: signer,
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
	if w.signer != nil && w.hasPendingRemote(ctx, msg) {
		raw, err = w.signer.Sign(msg.ReturnPath, raw)
		if err != nil {
			return err
		}
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
			rcpt.LastDiag = err.Error()
			if deliveryPermanent(err) {
				MarkPermanentFail(&msg, i)
				w.maybeSendDSN(ctx, e.ID, msg, *rcpt, raw, DSNActionFailed, err)
			} else {
				ScheduleNextRetry(&msg, i, w.policy, now)
				if w.maybeSendDelayDSN(ctx, e.ID, msg, i, raw, created, now, err) {
					MarkDelayNotified(&msg, i)
					changed = true
				}
			}
			changed = true
			continue
		}
		MarkDelivered(&msg, i)
		w.maybeSendDSN(ctx, e.ID, msg, *rcpt, raw, DSNActionDelivered, nil)
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
	raw, _ := w.queue.LoadRaw(ctx, msg)
	returnPath := strings.TrimSpace(msg.ReturnPath)
	for i, rcpt := range msg.Recipients {
		if !recipientPending(rcpt) || returnPath == "" {
			continue
		}
		rcpt.LastDiag = "delivery time expired"
		w.maybeSendDSN(ctx, e.ID, msg, rcpt, raw, DSNActionFailed, fmt.Errorf("delivery time expired"))
		MarkPermanentFail(&msg, i)
	}
	return w.queue.Delete(ctx, e.ID)
}

func (w *Worker) maybeSendDelayDSN(ctx context.Context, queueID uint32, msg storage.QueueMessage, rcptIdx int, raw []byte, created, now time.Time, err error) bool {
	rcpt := msg.Recipients[rcptIdx]
	if DelayNotified(rcpt) {
		return false
	}
	if w.policy.DelayNotifyAfter > 0 && now.Sub(created) < w.policy.DelayNotifyAfter {
		return false
	}
	w.maybeSendDSN(ctx, queueID, msg, rcpt, raw, DSNActionDelayed, err)
	return true
}

func (w *Worker) maybeSendDSN(ctx context.Context, queueID uint32, msg storage.QueueMessage, rcpt storage.QueueRecipient, raw []byte, action DSNAction, err error) {
	returnPath := strings.TrimSpace(msg.ReturnPath)
	if returnPath == "" {
		return
	}
	notify := NotifyFlagsFromStorage(rcpt.Notify)
	local := w.returnPathLocal(ctx, returnPath)
	remoteOK := w.remote != nil
	if !ShouldSendDSN(returnPath, notify, action, local, remoteOK) {
		return
	}

	diag := rcpt.LastDiag
	if diag == "" && err != nil {
		diag = err.Error()
	}
	status := dsnStatusFor(action, err)
	opts := DSNBuildOpts{
		ReturnPath: returnPath,
		FinalRcpt:  rcpt.Address,
		Orcpt:      rcpt.Orcpt,
		Envid:      msg.Envid,
		Ret:        RetMode(msg.Ret),
		Action:     action,
		Status:     status,
		Diagnostic: diag,
		QueueID:    queueID,
		OriginalRaw: raw,
	}
	bounce := BuildDSN(opts)
	if err := w.deliverBounce(ctx, returnPath, bounce); err != nil {
		w.log.Warn("dsn deliver failed", "return_path", returnPath, "action", action, slog.Any("err", err))
	}
}

func dsnStatusFor(action DSNAction, err error) string {
	switch action {
	case DSNActionDelivered:
		return "2.0.0"
	case DSNActionDelayed:
		if err != nil {
			return SMTPStatusFromError(err)
		}
		return "4.0.0"
	default:
		if err != nil {
			return SMTPStatusFromError(err)
		}
		return "5.0.0"
	}
}

func (w *Worker) returnPathLocal(ctx context.Context, returnPath string) bool {
	acc, _, err := w.dir.ResolveEmail(ctx, returnPath)
	return err == nil && acc.Active
}

func (w *Worker) deliverBounce(ctx context.Context, returnPath string, raw []byte) error {
	if w.returnPathLocal(ctx, returnPath) {
		acc, _, err := w.dir.ResolveEmail(ctx, returnPath)
		if err != nil {
			return err
		}
		_, err = w.inbox.Deliver(ctx, acc.ID, raw)
		return err
	}
	if w.remote == nil {
		return errors.New("mail: no remote delivery for bounce")
	}
	return w.remote.DeliverRemote(ctx, "", returnPath, raw)
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

func (w *Worker) hasPendingRemote(ctx context.Context, msg storage.QueueMessage) bool {
	if w.remote == nil {
		return false
	}
	for _, rcpt := range msg.Recipients {
		if !recipientPending(rcpt) {
			continue
		}
		if _, _, err := w.dir.ResolveEmail(ctx, rcpt.Address); errors.Is(err, directory.ErrNotFound) {
			return true
		}
	}
	return false
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
