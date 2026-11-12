package mail_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// stallRemote never answers for the tarpit domain until released, and records every other delivery
// and how many tarpit deliveries were in flight at once.
type stallRemote struct {
	release chan struct{}
	mu      sync.Mutex
	done    []string
	stalled int // tarpit deliveries in flight now
	peak    int // highest stalled seen
}

func (r *stallRemote) DeliverRemote(ctx context.Context, _, rcptTo string, _ []byte, _ *mail.RelayDSN) (string, error) {
	if strings.HasSuffix(rcptTo, "@tarpit.example") {
		r.mu.Lock()
		r.stalled++
		r.peak = max(r.peak, r.stalled)
		r.mu.Unlock()
		select {
		case <-r.release:
		case <-ctx.Done():
		}
		r.mu.Lock()
		r.stalled--
		r.mu.Unlock()
		return "250 late", nil
	}
	r.mu.Lock()
	r.done = append(r.done, rcptTo)
	r.mu.Unlock()
	return "250 ok", nil
}

// A remote that stalls (a tarpit using the full RFC timeouts) must not hold back the rest of the queue.
func TestWorkerSlowRemoteDoesNotBlockQueue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	blobs := blob.NewFS(t.TempDir() + "/blobs")
	q := mail.NewQueue(store, blobs)
	if _, err := q.Enqueue(ctx, "a@example.net", []string{"x@tarpit.example"}, []byte("Subject: 1\r\n\r\nslow\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(ctx, "a@example.net", []string{"bob@fast.example"}, []byte("Subject: 2\r\n\r\nfast\r\n")); err != nil {
		t.Fatal(err)
	}
	remote := &stallRemote{release: make(chan struct{})}
	w := mail.NewWorker(log.New("error"), q, mail.NewInbox(store, blobs), directory.NewLocal(store), remote, nil, mail.TestQueuePolicy())
	finished := make(chan struct{})
	go func() { w.ProcessOnce(ctx); close(finished) }()
	defer func() { close(remote.release); <-finished }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		remote.mu.Lock()
		n := len(remote.done)
		remote.mu.Unlock()
		if n == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the fast message waited behind the stalled one")
}

// recordSigner records the identity the worker signs with.
type recordSigner struct {
	mu  sync.Mutex
	ids []string
}

func (s *recordSigner) Sign(returnPath string, raw []byte) ([]byte, error) {
	s.mu.Lock()
	s.ids = append(s.ids, returnPath)
	s.mu.Unlock()
	return raw, nil
}

// A null-sender message from submission is DKIM-signed as the authenticated user, never left unsigned
// and never signed by its header From (which the user could set to another tenant's domain).
func TestWorkerSignsNullSenderAsAuthenticatedUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	blobs := blob.NewFS(t.TempDir() + "/blobs")
	q := mail.NewQueue(store, blobs)
	env := mail.EnvelopeDSN{ReturnPath: "", SignAs: "alice@example.net", Recipients: []mail.RcptDSN{{Address: "bob@fast.example", Notify: mail.NotifyDefault}}}
	if _, err := q.EnqueueDSN(ctx, env, []byte("From: ceo@other-tenant.example\r\nSubject: x\r\n\r\nhi\r\n")); err != nil {
		t.Fatal(err)
	}
	signer := &recordSigner{}
	remote := &stallRemote{release: make(chan struct{})}
	close(remote.release)
	mail.NewWorker(log.New("error"), q, mail.NewInbox(store, blobs), directory.NewLocal(store), remote, signer, mail.TestQueuePolicy()).ProcessOnce(ctx)
	if len(signer.ids) != 1 || signer.ids[0] != "alice@example.net" {
		t.Fatalf("signed as %q, want alice@example.net", signer.ids)
	}
}

// waitDelivered polls until remote has delivered n fast messages.
func waitDelivered(t *testing.T, remote *stallRemote, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		remote.mu.Lock()
		got := len(remote.done)
		remote.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("fast messages delivered: want %d in time", n)
}

// One destination never takes more than OutboundPerDestination slots, and a message queued while the
// tarpit deliveries are still stuck goes out on the next pass: passes do not wait for each other.
func TestWorkerPerDestinationCapAndNonBlockingPasses(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	blobs := blob.NewFS(t.TempDir() + "/blobs")
	q := mail.NewQueue(store, blobs)
	for range 2 * mail.OutboundPerDestination {
		if _, err := q.Enqueue(ctx, "a@example.net", []string{"x@tarpit.example"}, []byte("Subject: s\r\n\r\nslow\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	remote := &stallRemote{release: make(chan struct{})}
	w := mail.NewWorker(log.New("error"), q, mail.NewInbox(store, blobs), directory.NewLocal(store), remote, nil, mail.TestQueuePolicy())
	stopped := make(chan struct{})
	go func() { w.Run(ctx); close(stopped) }()
	defer func() { close(remote.release); cancel(); <-stopped }()

	time.Sleep(200 * time.Millisecond) // several passes while the tarpit holds its slots
	if _, err := q.Enqueue(ctx, "a@example.net", []string{"bob@fast.example"}, []byte("Subject: f\r\n\r\nfast\r\n")); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, remote, 1)
	remote.mu.Lock()
	peak := remote.peak
	remote.mu.Unlock()
	if peak != mail.OutboundPerDestination {
		t.Fatalf("tarpit deliveries in flight at once: %d, want %d", peak, mail.OutboundPerDestination)
	}
}
