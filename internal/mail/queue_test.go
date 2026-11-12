package mail_test

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

func TestQueueEnqueueAndDelete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	q := mail.NewQueue(store, blob.NewFS(t.TempDir()+"/blobs"))
	raw := []byte("queued body")
	id, err := q.Enqueue(ctx, "sender@example.com", []string{"a@b.c"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Fatalf("id %d", id)
	}

	entries, err := q.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != 1 {
		t.Fatalf("entries %+v", entries)
	}
	got, err := q.LoadRaw(ctx, entries[0].Msg)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("raw %q err %v", got, err)
	}
	if err := q.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	entries, err = q.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries %+v", entries)
	}
}

// Concurrent enqueues (SMTP sessions, worker DSNs, CLI) must get distinct ids: with a plain
// read-increment-write two of them could share one and the second entry overwrote the first.
func TestQueueConcurrentEnqueueUniqueIDs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	q := mail.NewQueue(store, blob.NewFS(t.TempDir()+"/blobs"))
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := q.Enqueue(ctx, "sender@example.com", []string{"a@b.c"}, []byte("body "+strconv.Itoa(i)))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	entries, err := q.ListAll(ctx)
	if err != nil || len(entries) != n {
		t.Fatalf("%d entries, %v; want %d (an id was reused)", len(entries), err, n)
	}
}
