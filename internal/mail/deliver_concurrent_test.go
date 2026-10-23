package mail_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

// Concurrent deliveries and flag changes on one mailbox, from two stores on the same file
// (daemon + CLI), must keep every message, distinct UIDs and MODSEQs, and exact counters.
func TestDeliverConcurrentSameAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := "file:" + t.TempDir() + "/store.sqlite"
	blobDir := t.TempDir() + "/blobs"
	var inboxes [2]*mail.Inbox
	for i := range inboxes {
		store, err := sqlite.Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		inboxes[i] = mail.NewInbox(store, blob.NewFS(blobDir))
	}
	acc, err := directory.SeedDev(ctx, directory.NewLocal(sqliteStoreFor(t, path)))
	if err != nil {
		t.Fatal(err)
	}

	const workers, each = 8, 25
	var wg sync.WaitGroup
	errCh := make(chan error, workers*each*2)
	ids := make(chan uint32, workers*each)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				raw := fmt.Appendf(nil, "From: a@example.org\r\nSubject: %d-%d\r\n\r\nbody\r\n", w, i)
				id, err := inboxes[w%2].Deliver(ctx, acc.ID, raw)
				if err != nil {
					errCh <- err
					continue
				}
				ids <- id
			}
		}()
	}
	// Flag every delivered message while deliveries are still running.
	var flagWG sync.WaitGroup
	flagWG.Add(1)
	go func() {
		defer flagWG.Done()
		for id := range ids {
			if err := inboxes[int(id)%2].SetFlags(ctx, acc.ID, id, mail.FlagSeen, 0); err != nil {
				errCh <- err
			}
		}
	}()
	wg.Wait()
	close(ids)
	flagWG.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	ib := inboxes[0]
	msgs, err := ib.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != workers*each {
		t.Fatalf("inbox has %d messages, want %d", len(msgs), workers*each)
	}
	uids, modseqs := map[uint32]bool{}, map[uint64]bool{}
	for _, m := range msgs {
		if uids[m.UID] {
			t.Errorf("duplicate UID %d", m.UID)
		}
		uids[m.UID] = true
		if modseqs[m.Meta.ModSeq] {
			t.Errorf("duplicate MODSEQ %d", m.Meta.ModSeq)
		}
		modseqs[m.Meta.ModSeq] = true
		if m.Meta.Flags&mail.FlagSeen == 0 {
			t.Errorf("message %d lost its \\Seen flag", m.EmailID)
		}
	}
	summaries, err := ib.ListMailboxSummaries(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range summaries {
		if s.ID == mail.InboxMailboxID && s.Messages != workers*each {
			t.Errorf("INBOX count %d, want %d", s.Messages, workers*each)
		}
	}
	q, err := ib.QuotaStatus(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if q.MessagesUsed != workers*each {
		t.Errorf("quota messages %d, want %d", q.MessagesUsed, workers*each)
	}
}

func sqliteStoreFor(t *testing.T, path string) *sqlite.Store {
	t.Helper()
	store, err := sqlite.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
