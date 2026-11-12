// Background worker that drains the outbound mail queue.
package mail

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/storage"
)

// RemoteDeliverer submits mail to remote recipients (relay or MX).
type RemoteDeliverer interface {
	// DeliverRemote returns the accepting server's reply on success.
	DeliverRemote(ctx context.Context, mailFrom, rcptTo string, data []byte) (string, error)
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

	lastPurge time.Time

	// In-flight deliveries, by entry and by destination domain (see drain).
	mu       sync.Mutex
	inflight map[uint32]bool
	perDest  map[string]int
	wg       sync.WaitGroup
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

// Run polls the queue until ctx is canceled, then waits for the deliveries in flight (their
// connections close on cancellation).
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.policy.RunDelay)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.wg.Wait()
			return
		case <-ticker.C:
			w.drain(ctx)
		}
	}
}

// ProcessOnce starts one pass and waits for its deliveries (for tests).
func (w *Worker) ProcessOnce(ctx context.Context) {
	w.drain(ctx)
	w.wg.Wait()
}

// Outbound concurrency. A pass never waits for the deliveries it starts: an entry stays "in flight"
// until its goroutine ends, and later passes start whatever is free. So a slow or tarpitting remote
// (RFC 5321 timeouts reach 10 minutes per command) holds only its own slots, never the queue, and at
// most OutboundPerDestination of them (Postfix: 20 per domain out of 100).
const (
	OutboundConcurrency    = 16
	OutboundPerDestination = 4
)

// drain starts a delivery for every pending entry that is not already in flight, within the limits.
func (w *Worker) drain(ctx context.Context) {
	entries, err := w.queue.ListPending(ctx)
	if err != nil {
		w.log.Warn("queue list", slog.Any("err", err))
		return
	}
	w.mu.Lock()
	if w.inflight == nil {
		w.inflight = map[uint32]bool{}
		w.perDest = map[string]int{}
	}
	for _, e := range entries {
		if ctx.Err() != nil || len(w.inflight) >= OutboundConcurrency {
			break
		}
		dest := destination(e.Msg)
		if w.inflight[e.ID] || w.perDest[dest] >= OutboundPerDestination {
			continue
		}
		w.inflight[e.ID] = true
		w.perDest[dest]++
		w.wg.Add(1)
		go func() {
			defer func() {
				w.mu.Lock()
				delete(w.inflight, e.ID)
				w.perDest[dest]--
				w.mu.Unlock()
				w.wg.Done()
			}()
			if err := w.deliverEntry(ctx, e); err != nil && ctx.Err() == nil {
				w.log.Warn("queue deliver", "id", e.ID, slog.Any("err", err))
			}
		}()
	}
	w.mu.Unlock()
	w.purgeCompleted(ctx, time.Now())
}

// destination is the domain of the entry's first pending recipient: the concurrency bucket.
func destination(msg storage.QueueMessage) string {
	for _, r := range msg.Recipients {
		if recipientPending(r) {
			if at := strings.LastIndexByte(r.Address, '@'); at >= 0 {
				return strings.ToLower(r.Address[at+1:])
			}
			return ""
		}
	}
	return ""
}

// purgeInterval bounds how often finished entries are scanned for expiry.
const purgeInterval = time.Minute

// purgeCompleted deletes finished entries older than KeepCompleted (or unstamped ones).
func (w *Worker) purgeCompleted(ctx context.Context, now time.Time) {
	if now.Sub(w.lastPurge) < min(purgeInterval, w.policy.KeepCompleted) {
		return
	}
	w.lastPurge = now
	entries, err := w.queue.ListAll(ctx)
	if err != nil {
		w.log.Warn("queue list", slog.Any("err", err))
		return
	}
	w.mu.Lock()
	busy := maps.Clone(w.inflight)
	w.mu.Unlock()
	for _, e := range entries {
		if pendingRecipients(e.Msg) > 0 || busy[e.ID] {
			continue
		}
		if e.Msg.Done == 0 || now.Sub(time.UnixMilli(e.Msg.Done)) > w.policy.KeepCompleted {
			if err := w.queue.Delete(ctx, e.ID); err != nil {
				w.log.Warn("queue purge", "id", e.ID, slog.Any("err", err))
			}
		}
	}
}

// finishEntry keeps a message with no pending recipients as history, or deletes it when retention is off.
func (w *Worker) finishEntry(ctx context.Context, id uint32, msg storage.QueueMessage, now time.Time) error {
	if w.policy.KeepCompleted <= 0 {
		return w.queue.Delete(ctx, id)
	}
	if msg.Done == 0 {
		msg.Done = now.UnixMilli()
	}
	return w.queue.Save(ctx, id, msg)
}

func (w *Worker) deliverEntry(ctx context.Context, e QueueEntry) error {
	msg := e.Msg
	if pendingRecipients(msg) == 0 {
		return w.finishEntry(ctx, e.ID, msg, time.Now())
	}
	if IsHeld(msg) {
		return nil
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
	// Sign the exact bytes that go on the wire (stored DATA messages use bare LF).
	raw = CRLF(raw)
	if w.signer != nil && w.hasPendingRemote(ctx, msg) {
		raw, err = w.signer.Sign(cmp.Or(msg.ReturnPath, msg.SignAs), raw)
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
		reply, err := w.deliverTo(ctx, msg.ReturnPath, rcpt.Address, raw)
		if err != nil {
			w.log.Warn("queue rcpt failed", "queue_id", e.ID, "rcpt", rcpt.Address, slog.Any("err", err))
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
		rcpt.LastDiag = reply
		MarkDelivered(&msg, i)
		w.maybeSendDSN(ctx, e.ID, msg, *rcpt, raw, DSNActionDelivered, nil)
		changed = true
	}

	if !changed {
		return nil
	}
	if AllDone(msg) {
		return w.finishEntry(ctx, e.ID, msg, now)
	}
	return w.queue.Save(ctx, e.ID, msg)
}

// expireEntry notifies return-path for pending recipients and removes the queue entry.
func (w *Worker) expireEntry(ctx context.Context, e QueueEntry) error {
	msg := e.Msg
	w.log.Info("queue message expired", "id", e.ID, "return_path", msg.ReturnPath)
	raw, _ := w.queue.LoadRaw(ctx, msg)
	returnPath := strings.TrimSpace(msg.ReturnPath)
	for i := range msg.Recipients {
		if !recipientPending(msg.Recipients[i]) {
			continue
		}
		msg.Recipients[i].LastDiag = "delivery time expired"
		if returnPath != "" {
			w.maybeSendDSN(ctx, e.ID, msg, msg.Recipients[i], raw, DSNActionFailed, fmt.Errorf("delivery time expired"))
		}
		MarkPermanentFail(&msg, i)
	}
	return w.finishEntry(ctx, e.ID, msg, time.Now())
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
		ReturnPath:  returnPath,
		FinalRcpt:   rcpt.Address,
		Orcpt:       rcpt.Orcpt,
		Envid:       msg.Envid,
		Ret:         RetMode(msg.Ret),
		Action:      action,
		Status:      status,
		Diagnostic:  diag,
		QueueID:     queueID,
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
	_, err := w.remote.DeliverRemote(ctx, "", returnPath, raw)
	return err
}

// deliverTo returns a short delivery record on success (local mailbox or the remote server's reply).
func (w *Worker) deliverTo(ctx context.Context, returnPath, rcpt string, raw []byte) (string, error) {
	acc, _, err := w.dir.ResolveEmail(ctx, rcpt)
	if err == nil {
		if !acc.Active {
			return "", directory.ErrInactive
		}
		if _, err = w.inbox.Deliver(ctx, acc.ID, raw); err != nil {
			return "", err
		}
		return "delivered to local mailbox", nil
	}
	if !errors.Is(err, directory.ErrNotFound) {
		return "", err
	}
	if w.remote == nil {
		return "", errors.New("mail: no remote delivery configured")
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
