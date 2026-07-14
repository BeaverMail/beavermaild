package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestMoveAndCopyMessages(t *testing.T) {
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
	id, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nmove me\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := inbox.MoveMessages(ctx, acc.ID, []uint32{id}, mail.TrashMailboxID); err != nil {
		t.Fatal(err)
	}
	inboxMsgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil || len(inboxMsgs) != 0 {
		t.Fatalf("inbox after move %d err %v", len(inboxMsgs), err)
	}
	trashMsgs, err := inbox.List(ctx, acc.ID, mail.TrashMailboxID)
	if err != nil || len(trashMsgs) != 1 {
		t.Fatalf("trash after move %d err %v", len(trashMsgs), err)
	}

	id2, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\ncopy me\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := inbox.CopyMessages(ctx, acc.ID, []uint32{id2}, mail.SentMailboxID); err != nil {
		t.Fatal(err)
	}
	sent, err := inbox.List(ctx, acc.ID, mail.SentMailboxID)
	if err != nil || len(sent) != 1 {
		t.Fatalf("sent after copy %d err %v", len(sent), err)
	}
}

func TestCreateDeleteMailbox(t *testing.T) {
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
	mb, err := inbox.CreateMailbox(ctx, acc.ID, "Archive")
	if err != nil {
		t.Fatal(err)
	}
	if mb.Name != "Archive" {
		t.Fatalf("name %q", mb.Name)
	}
	if err := inbox.DeleteMailbox(ctx, acc.ID, mb.ID); err != nil {
		t.Fatal(err)
	}
	if err := inbox.DeleteMailbox(ctx, acc.ID, mail.InboxMailboxID); err != mail.ErrSystemMailbox {
		t.Fatalf("delete inbox err %v", err)
	}
}

func TestRenameMailbox(t *testing.T) {
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
	mb, err := inbox.CreateMailbox(ctx, acc.ID, "Old")
	if err != nil {
		t.Fatal(err)
	}
	_ = mb
	renamed, err := inbox.RenameMailbox(ctx, acc.ID, "Old", "New")
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Name != "New" || renamed.UIDValidity != 2 {
		t.Fatalf("renamed %+v", renamed)
	}
	if _, err := inbox.ResolveMailbox(ctx, acc.ID, "New"); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.RenameMailbox(ctx, acc.ID, "INBOX", "X"); err != mail.ErrSystemMailbox {
		t.Fatalf("rename inbox err %v", err)
	}
	if _, err := inbox.CreateMailbox(ctx, acc.ID, "Taken"); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.RenameMailbox(ctx, acc.ID, "New", "Taken"); err != mail.ErrMailboxExists {
		t.Fatalf("duplicate rename err %v", err)
	}
}
