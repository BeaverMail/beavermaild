package mail_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestInboxSetFlagsPersists(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dir := directory.NewLocal(store)
	acc, err := directory.SeedDev(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	id, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nx\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.SetFlags(ctx, acc.ID, id, mail.FlagSeen, 0); err != nil {
		t.Fatal(err)
	}
	meta, err := inbox.GetMeta(ctx, acc.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Flags&mail.FlagSeen == 0 {
		t.Fatalf("flags %#x", meta.Flags)
	}
}

func TestWorkerExpireBouncesReturnPath(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dir := directory.NewLocal(store)
	acc, err := directory.SeedDev(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)
	raw := mail.BuildSimpleMessage("alice@localhost", "remote@example.com", "expire me")
	id, err := queue.Enqueue(ctx, "alice@localhost", []string{"remote@example.com"}, raw)
	if err != nil {
		t.Fatal(err)
	}

	policy := mail.TestQueuePolicy()
	policy.MaxLifetime = time.Millisecond
	w := mail.NewWorker(log.New("error"), queue, inbox, dir, nil, policy)
	w.ProcessOnce(ctx)
	time.Sleep(5 * time.Millisecond)
	w.ProcessOnce(ctx)

	pending, err := queue.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("queue still pending %+v", pending)
	}

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox %d messages", len(msgs))
	}
	body, err := inbox.LoadRaw(ctx, msgs[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Delivery Status Notification") {
		t.Fatalf("bounce body %q", body)
	}
	if !strings.Contains(string(body), "remote@example.com") {
		t.Fatalf("bounce body %q", body)
	}
	_ = id
}
