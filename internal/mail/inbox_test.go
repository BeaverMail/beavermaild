package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestInboxDeliver(t *testing.T) {
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

	raw := []byte("From: a@b\r\n\r\nbody")
	id, err := inbox.Deliver(ctx, acc.ID, raw)
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Fatalf("id %d", id)
	}

	key := storage.AppendKey(nil, storage.SubspaceMail, acc.ID, id, byte(storage.CollectionEmail), nil)
	wire, err := store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	var meta storage.EmailMeta
	if err := storage.UnmarshalPersist(wire, &meta); err != nil {
		t.Fatal(err)
	}
	if !meta.HasBlob() || meta.Size != uint32(len(raw)) {
		t.Fatalf("meta %+v", meta)
	}
}
