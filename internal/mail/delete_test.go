package mail_test

import (
	"context"
	"os"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestDeleteMessageRemovesBlobWhenSoleRef(t *testing.T) {
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
	blobPath := blobs.Path(msgs[0].Meta.BlobHash)

	if err := inbox.DeleteMessage(ctx, acc.ID, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatalf("blob still on disk after expunge: %v", err)
	}
}

func TestDeleteMessageKeepsSharedBlobAfterCopy(t *testing.T) {
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
	sent, err := inbox.List(ctx, acc.ID, mail.SentMailboxID)
	if err != nil || len(sent) != 1 {
		t.Fatalf("sent %+v err %v", sent, err)
	}
	blobPath := blobs.Path(sent[0].Meta.BlobHash)

	if err := inbox.DeleteMessage(ctx, acc.ID, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatalf("shared blob removed too early: %v", err)
	}
}

func TestDeleteMessageRemovesFromList(t *testing.T) {
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

	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	id, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nx\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.DeleteMessage(ctx, acc.ID, id); err != nil {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("msgs %+v", msgs)
	}
}
