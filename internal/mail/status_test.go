package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestStatusIndexOnlyFields(t *testing.T) {
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
	if err := inbox.EnsureMailboxes(ctx, acc.ID); err != nil {
		t.Fatal(err)
	}

	id1, err := inbox.Deliver(ctx, acc.ID, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("b")); err != nil {
		t.Fatal(err)
	}

	st, err := inbox.Status(ctx, acc.ID, mail.InboxMailboxID, []string{"MESSAGES", "UIDNEXT", "UIDVALIDITY"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Messages != 2 || st.UIDNext != id1+2 || st.UIDValidity == 0 {
		t.Fatalf("index status %+v id1=%d", st, id1)
	}
}

func TestStatusFlagFieldsIncludeUnseenRecent(t *testing.T) {
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
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("fresh")); err != nil {
		t.Fatal(err)
	}

	st, err := inbox.Status(ctx, acc.ID, mail.InboxMailboxID, []string{"UNSEEN", "RECENT"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Unseen != 1 || st.Recent != 1 {
		t.Fatalf("flags status %+v", st)
	}
}
