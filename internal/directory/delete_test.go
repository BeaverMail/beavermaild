package directory_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestDeleteAccountNotFound(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	blobs := blob.NewFS(t.TempDir() + "/blobs")
	_, err := d.DeleteAccount(context.Background(), "missing@test.local", blobs)
	if !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestDeleteAccountRemovesMailAndBlob(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	d := directory.NewLocal(store)
	dom, _, err := d.EnsureDomain(ctx, directory.DefaultTenantID, "del.test")
	if err != nil {
		t.Fatal(err)
	}
	acc, err := d.CreateAccount(ctx, dom.ID, "bob", "secret")
	if err != nil {
		t.Fatal(err)
	}

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatal("want one message")
	}
	blobPath := blobs.Path(msgs[0].Meta.BlobHash)

	res, err := d.DeleteAccount(ctx, "bob@del.test", blobs)
	if err != nil {
		t.Fatal(err)
	}
	if res.MessagesRemoved != 1 || res.BlobsRemoved != 1 || res.Email != "bob@del.test" {
		t.Fatalf("result %+v", res)
	}
	_, _, err = d.ResolveEmail(ctx, "bob@del.test")
	if !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("account still exists: %v", err)
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatalf("blob still on disk: %v", err)
	}
}
