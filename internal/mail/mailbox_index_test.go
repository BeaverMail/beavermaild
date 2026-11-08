package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

func TestMailboxIndexBackfillAndList(t *testing.T) {
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

	// Legacy row without index (simulate pre-migration store).
	emailID := uint32(1)
	meta := storage.EmailMeta{
		Version:    1,
		MailboxID:  mail.InboxMailboxID,
		ReceivedAt: 1,
		Size:       3,
		Flags:      mail.FlagRecent,
	}
	hash, err := blobs.Put(ctx, []byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	meta.BlobHash = hash
	wire, err := storage.MarshalPersist(nil, 1, meta)
	if err != nil {
		t.Fatal(err)
	}
	batch := storage.NewBatch().WithAccount(acc.ID)
	if err := batch.Set(storage.SubspaceMail, storage.DocumentSuffix(storage.CollectionEmail, emailID, nil), wire); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, batch); err != nil {
		t.Fatal(err)
	}

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].UID != 1 {
		t.Fatalf("msgs %+v", msgs)
	}
	readyKey := storage.AppendMailboxIndexKey(nil, acc.ID, mail.InboxMailboxID, storage.MailboxIndexSentinelEmailID)
	if _, err := store.Get(ctx, readyKey); err != nil {
		t.Fatalf("sentinel missing: %v", err)
	}
}

func TestMailboxIndexMoveUpdatesMembership(t *testing.T) {
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
	if err := inbox.EnsureMailboxes(ctx, acc.ID); err != nil {
		t.Fatal(err)
	}

	id, err := inbox.Deliver(ctx, acc.ID, []byte("mv"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.MoveMessages(ctx, acc.ID, []uint32{id}, mail.TrashMailboxID); err != nil {
		t.Fatal(err)
	}
	inboxMsgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	trashMsgs, err := inbox.List(ctx, acc.ID, mail.TrashMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(inboxMsgs) != 0 || len(trashMsgs) != 1 || trashMsgs[0].UID != 1 {
		t.Fatalf("inbox=%d trash=%+v", len(inboxMsgs), trashMsgs)
	}
	idxKey := storage.AppendMailboxIndexKey(nil, acc.ID, mail.InboxMailboxID, id)
	if _, err := store.Get(ctx, idxKey); err == nil {
		t.Fatal("index row still in INBOX after move")
	}
}
