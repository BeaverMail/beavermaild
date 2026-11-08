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

func TestAppendSequentialIMAPUIDs(t *testing.T) {
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
	sent, err := inbox.ResolveMailbox(ctx, acc.ID, "Sent")
	if err != nil {
		t.Fatal(err)
	}

	id1, err := inbox.Append(ctx, acc.ID, sent.ID, []byte("a"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := inbox.Append(ctx, acc.ID, sent.ID, []byte("b"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	msgs, err := inbox.List(ctx, acc.ID, sent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].UID != 1 || msgs[1].UID != 2 {
		t.Fatalf("uids %+v", msgs)
	}
	if msgs[0].EmailID != id1 || msgs[1].EmailID != id2 {
		t.Fatalf("email ids %+v", msgs)
	}

	st, err := inbox.Status(ctx, acc.ID, sent.ID, []string{"UIDNEXT"})
	if err != nil {
		t.Fatal(err)
	}
	if st.UIDNext != 3 {
		t.Fatalf("uidnext %d", st.UIDNext)
	}
}

func TestCopyIndependentIMAPUID(t *testing.T) {
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

	_, err = inbox.Deliver(ctx, acc.ID, []byte("inbox"))
	if err != nil {
		t.Fatal(err)
	}
	inboxMsgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil || len(inboxMsgs) != 1 {
		t.Fatal(err)
	}
	srcUID := inboxMsgs[0].UID

	_, destUIDs, err := inbox.CopyMessages(ctx, acc.ID, []uint32{inboxMsgs[0].EmailID}, mail.SentMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(destUIDs) != 1 || destUIDs[0] != 1 {
		t.Fatalf("dest uids %v", destUIDs)
	}
	if destUIDs[0] == srcUID && srcUID > 1 {
		t.Fatalf("sent uid should start at 1, got %d src %d", destUIDs[0], srcUID)
	}
}

func TestLegacyBackfillPreservesEmailIDAsIMAPUID(t *testing.T) {
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

	emailID := uint32(42)
	hash, err := blobs.Put(ctx, []byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	meta := storage.EmailMeta{
		Version:    1,
		MailboxID:  mail.InboxMailboxID,
		ReceivedAt: 1,
		Size:       6,
		Flags:      mail.FlagRecent,
		BlobHash:   hash,
	}
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
	if len(msgs) != 1 || msgs[0].UID != 42 {
		t.Fatalf("msgs %+v", msgs)
	}
	st, err := inbox.Status(ctx, acc.ID, mail.InboxMailboxID, []string{"UIDNEXT"})
	if err != nil {
		t.Fatal(err)
	}
	if st.UIDNext != 43 {
		t.Fatalf("uidnext %d", st.UIDNext)
	}
}
