package mail_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestQueueHoldRetryCancel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	q := mail.NewQueue(store, blob.NewFS(t.TempDir()+"/blobs"))

	id, err := q.Enqueue(ctx, "a@localhost", []string{"b@example.com"}, []byte("Subject: x\r\n\r\nbody"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := q.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	e.Msg.Recipients[0].NextDue = time.Now().Add(time.Hour).UnixMilli()
	if err := q.Save(ctx, id, e.Msg); err != nil {
		t.Fatal(err)
	}

	if err := q.Hold(ctx, id); err != nil {
		t.Fatal(err)
	}
	e, err = q.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !mail.IsHeld(e.Msg) {
		t.Fatal("expected held")
	}

	if err := q.RetryNow(ctx, id, ""); err != nil {
		t.Fatal(err)
	}
	e, err = q.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if mail.IsHeld(e.Msg) {
		t.Fatal("retry should clear hold")
	}
	if e.Msg.Recipients[0].NextDue != 0 {
		t.Fatalf("next_due=%d want 0", e.Msg.Recipients[0].NextDue)
	}

	if err := q.Cancel(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Get(ctx, id); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("after cancel: %v", err)
	}
}
