package mail_test

import (
	"context"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestWorkerWaitsBackoffBeforeRetry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	queue := mail.NewQueue(store, blob.NewFS(t.TempDir()+"/blobs"))
	dir := directory.NewLocal(store)
	raw := mail.BuildSimpleMessage("s@e.com", "remote@example.com", "x")
	if _, err := queue.Enqueue(ctx, "s@e.com", []string{"remote@example.com"}, raw); err != nil {
		t.Fatal(err)
	}

	policy := mail.TestQueuePolicy()
	w := mail.NewWorker(log.New("error"), queue, nil, dir, nil, policy)
	w.ProcessOnce(ctx)

	entries, err := queue.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("pending %d", len(entries))
	}
	rcpt := entries[0].Msg.Recipients[0]
	if rcpt.Retry != 1 || rcpt.LastAttempt == 0 {
		t.Fatalf("rcpt after fail %+v", rcpt)
	}

	w.ProcessOnce(ctx)
	entries, err = queue.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Msg.Recipients[0].Retry != 1 {
		t.Fatal("should not retry inside cooldown window")
	}

	time.Sleep(250 * time.Millisecond)
	w.ProcessOnce(ctx)
	entries, err = queue.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Msg.Recipients[0].Retry != 2 {
		t.Fatalf("rcpt after second try %+v", entries[0].Msg.Recipients[0])
	}
}
