package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
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
