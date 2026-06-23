package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestInboxList(t *testing.T) {
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
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("bb")); err != nil {
		t.Fatal(err)
	}

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].UID != 1 || msgs[1].UID != 2 {
		t.Fatalf("msgs %+v", msgs)
	}
	raw, err := inbox.LoadRaw(ctx, msgs[1].Meta)
	if err != nil || string(raw) != "bb" {
		t.Fatalf("raw %q err %v", raw, err)
	}
}
