package blob_test

import (
	"context"
	"os"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestStillReferencedAfterCopy(t *testing.T) {
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
	if _, err := inbox.CopyMessages(ctx, acc.ID, []uint32{id}, mail.SentMailboxID); err != nil {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := blob.StillReferenced(ctx, store, msgs[0].Meta.BlobHash)
	if err != nil {
		t.Fatal(err)
	}
	if !ref {
		t.Fatal("expected shared blob to stay referenced")
	}
}

func TestRemoveIfUnreferencedDropsSoleBlob(t *testing.T) {
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
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	hash := msgs[0].Meta.BlobHash
	path := blobs.Path(hash)

	if err := inbox.DeleteMessage(ctx, acc.ID, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("blob still present: %v", err)
	}
}
