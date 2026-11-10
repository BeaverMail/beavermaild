package mail_test

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// TestDeleteMessageBlobRemovedByGC checks a deleted message's sole blob stays on disk until GC.
func TestDeleteMessageBlobRemovedByGC(t *testing.T) {
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
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatalf("blob removed by the delete itself: %v", err)
	}
	if _, err := blob.GC(ctx, store, blobs, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatalf("blob still on disk after GC: %v", err)
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
	if _, _, err := inbox.CopyMessages(ctx, acc.ID, []uint32{id}, mail.SentMailboxID); err != nil {
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

func TestDeleteMessageBumpsHighestModSeq(t *testing.T) {
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

	id, err := inbox.Deliver(ctx, acc.ID, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := inbox.HighestModSeq(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.DeleteMessage(ctx, acc.ID, id); err != nil {
		t.Fatal(err)
	}
	after, err := inbox.HighestModSeq(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("HighestModSeq before=%d after=%d", before, after)
	}
}

// TestExpungeMessagesChecksCurrentState checks EXPUNGE only removes messages still flagged \Deleted
// in the expected mailbox, as stored now (another session may have changed them), and keeps the
// mailbox count and quota in step for a batch.
func TestExpungeMessagesChecksCurrentState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	acc, err := directory.SeedDev(ctx, directory.NewLocal(store))
	if err != nil {
		t.Fatal(err)
	}
	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	var ids []uint32
	for i := range 3 {
		id, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nmsg "+string(rune('0'+i))+"\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	expunge := func(mailboxID uint32, want ...uint32) {
		t.Helper()
		got, err := inbox.ExpungeMessages(ctx, acc.ID, mailboxID, ids)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("expunged %v, want %v", got, want)
		}
	}
	expunge(mail.InboxMailboxID) // none flagged \Deleted
	for _, id := range ids[:2] {
		if err := inbox.SetFlags(ctx, acc.ID, id, mail.FlagDeleted, 0); err != nil {
			t.Fatal(err)
		}
	}
	before, err := inbox.QuotaStatus(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	expunge(mail.DraftsMailboxID) // wrong mailbox
	expunge(mail.InboxMailboxID, ids[0], ids[1])
	expunge(mail.InboxMailboxID) // already gone
	st, err := inbox.Status(ctx, acc.ID, mail.InboxMailboxID, []string{"MESSAGES"})
	if err != nil {
		t.Fatal(err)
	}
	after, err := inbox.QuotaStatus(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Messages != 1 || after.MessagesUsed != before.MessagesUsed-2 {
		t.Fatalf("messages %d, quota messages %d -> %d", st.Messages, before.MessagesUsed, after.MessagesUsed)
	}
}
