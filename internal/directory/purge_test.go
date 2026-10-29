package directory_test

import (
	"context"
	"os"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

func TestPurgeAccountRemovesBlobWhenSoleRef(t *testing.T) {
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

	blobDir := t.TempDir() + "/blobs"
	blobs := blob.NewFS(blobDir)
	inbox := mail.NewInbox(store, blobs)

	raw := []byte("From: a@b\r\n\r\nbody")
	if _, err := inbox.Deliver(ctx, acc.ID, raw); err != nil {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || !msgs[0].Meta.HasBlob() {
		t.Fatalf("messages %+v", msgs)
	}
	blobPath := blobs.Path(msgs[0].Meta.BlobHash)
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatalf("blob before purge: %v", err)
	}

	res, err := dir.DeleteAccount(ctx, "alice@localhost", blobs)
	if err != nil {
		t.Fatal(err)
	}
	if res.MessagesRemoved != 1 || res.BlobsRemoved != 1 {
		t.Fatalf("delete result %+v", res)
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatalf("blob still on disk: %v", err)
	}
}

func TestPurgeAccountKeepsSharedBlob(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dir := directory.NewLocal(store)
	dom, _, err := dir.EnsureDomain(ctx, directory.DefaultTenantID, "shared.test")
	if err != nil {
		t.Fatal(err)
	}
	acc1, err := dir.CreateAccount(ctx, dom.ID, "a", "secret")
	if err != nil {
		t.Fatal(err)
	}
	acc2, err := dir.CreateAccount(ctx, dom.ID, "b", "secret")
	if err != nil {
		t.Fatal(err)
	}

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	raw := []byte("From: a@b\r\n\r\nsame body")

	if _, err := inbox.Deliver(ctx, acc1.ID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, acc2.ID, raw); err != nil {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc1.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatal("want one message on acc1")
	}
	blobPath := blobs.Path(msgs[0].Meta.BlobHash)

	res, err := dir.DeleteAccount(ctx, "a@shared.test", blobs)
	if err != nil {
		t.Fatal(err)
	}
	if res.MessagesRemoved != 1 || res.BlobsRemoved != 0 {
		t.Fatalf("delete acc1 %+v", res)
	}
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatalf("shared blob removed too early: %v", err)
	}

	res, err = dir.DeleteAccount(ctx, "b@shared.test", blobs)
	if err != nil {
		t.Fatal(err)
	}
	if res.BlobsRemoved != 1 {
		t.Fatalf("delete acc2 %+v", res)
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatalf("blob still on disk: %v", err)
	}
}
