package mail_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// TestConcurrentAppendsSameAccount checks the per-account write lock: many concurrent APPENDs to
// one mailbox all succeed (none gives up on contention) and get distinct UIDs.
func TestConcurrentAppendsSameAccount(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	acc, err := directory.SeedDev(ctx, directory.NewLocal(store))
	if err != nil {
		t.Fatal(err)
	}
	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))

	const workers, each = 32, 4
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := range workers {
		wg.Go(func() {
			for i := range each {
				raw := []byte("From: a@b\r\nSubject: " + string(rune('A'+w%26)) + string(rune('a'+i)) + "\r\n\r\nx\r\n")
				if _, err := inbox.Append(ctx, acc.ID, mail.InboxMailboxID, raw, 0, 0); err != nil {
					errs <- err
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != workers*each {
		t.Fatalf("%d messages, want %d", len(msgs), workers*each)
	}
	uids := map[uint32]bool{}
	for _, m := range msgs {
		if uids[m.UID] {
			t.Fatalf("duplicate UID %d", m.UID)
		}
		uids[m.UID] = true
	}
}

// TestNestedUpdatesDoNotWait checks that updates opening another update of the same account
// (CREATE resolves the name, which ensures the system folders) reuse the lock instead of waiting
// for it until the lock timeout.
func TestNestedUpdatesDoNotWait(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	acc, err := directory.SeedDev(ctx, directory.NewLocal(store))
	if err != nil {
		t.Fatal(err)
	}
	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))

	start := time.Now()
	mb, err := inbox.CreateMailbox(ctx, acc.ID, "Work/Sub", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.DeleteMailbox(ctx, acc.ID, mb.ID); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("create+delete took %v: a nested update waited for the account lock", d)
	}
}

// TestRecentClaimedOnce checks that sessions racing to claim a new message's \Recent (without the
// account lock) leave exactly one winner.
func TestRecentClaimedOnce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	acc, err := directory.SeedDev(ctx, directory.NewLocal(store))
	if err != nil {
		t.Fatal(err)
	}
	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	id, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nnew\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	winners := 0
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			got, err := inbox.ClearRecentFlagsOf(ctx, acc.ID, mail.InboxMailboxID, []uint32{id})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			winners += len(got)
			mu.Unlock()
		})
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("%d sessions claimed \\Recent, want 1", winners)
	}
}
