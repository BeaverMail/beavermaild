package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

func TestQueueListAllAndRecipientStatus(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	q := mail.NewQueue(store, blob.NewFS(t.TempDir()+"/blobs"))
	id, err := q.Enqueue(ctx, "from@example.com", []string{"a@b.c", "d@e.f"}, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	all, err := q.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].ID != id {
		t.Fatalf("all %+v", all)
	}

	mail.MarkDelivered(&all[0].Msg, 0)
	if err := q.Save(ctx, id, all[0].Msg); err != nil {
		t.Fatal(err)
	}

	pending, err := q.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending len %d", len(pending))
	}
	if mail.RecipientStatus(pending[0].Msg.Recipients[0]) != "delivered" {
		t.Fatal("rcpt 0 should be delivered")
	}
	if mail.RecipientStatus(pending[0].Msg.Recipients[1]) != "pending" {
		t.Fatal("rcpt 1 should be pending")
	}

	all, err = q.ListAll(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("all %+v err %v", all, err)
	}
}

func TestQueueListAllEmpty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	q := mail.NewQueue(store, blob.NewFS(t.TempDir()+"/blobs"))
	all, err := q.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Fatalf("got %d", len(all))
	}
}
