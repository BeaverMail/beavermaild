package mail_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
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
	mb, err := inbox.CreateMailbox(ctx, acc.ID, "Archive", true)
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
	// Created again it may reuse the id, so UIDVALIDITY must change (RFC 3501 2.3.1.1).
	again, err := inbox.CreateMailbox(ctx, acc.ID, "Archive", true)
	if err != nil {
		t.Fatal(err)
	}
	if again.UIDValidity == mb.UIDValidity {
		t.Fatalf("recreated mailbox kept UIDVALIDITY %d", mb.UIDValidity)
	}
	st, err := inbox.ResolveMailbox(ctx, acc.ID, "Archive")
	if err != nil {
		t.Fatal(err)
	}
	if st.UIDValidity != again.UIDValidity {
		t.Fatalf("stored UIDVALIDITY %d, CREATE returned %d", st.UIDValidity, again.UIDValidity)
	}
}

func TestCreateMailboxCreatesParents(t *testing.T) {
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
	if _, err := inbox.CreateMailbox(ctx, acc.ID, "Projects", true); err != nil {
		t.Fatal(err)
	}
	mb, err := inbox.CreateMailbox(ctx, acc.ID, "projects/2026/Q1", true)
	if err != nil {
		t.Fatal(err)
	}
	if mb.Name != "projects/2026/Q1" {
		t.Fatalf("name %q", mb.Name)
	}
	notes, err := inbox.CreateMailbox(ctx, acc.ID, "Notes/", true)
	if err != nil {
		t.Fatal(err)
	}
	if notes.Name != "Notes" {
		t.Fatalf("trailing delimiter kept: %q", notes.Name)
	}
	if _, err := inbox.CreateMailbox(ctx, acc.ID, "Projects/2026", true); err != mail.ErrMailboxExists {
		t.Fatalf("parent not created: %v", err)
	}

	mboxes, err := inbox.ListMailboxes(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[uint32]bool{}
	got := map[string]bool{}
	for _, m := range mboxes {
		if ids[m.ID] {
			t.Fatalf("duplicate id %d in %+v", m.ID, mboxes)
		}
		ids[m.ID] = true
		got[m.Name] = true
	}
	// The existing "Projects" is reused case-insensitively, not duplicated as "projects".
	for _, want := range []string{"Projects", "projects/2026", "projects/2026/Q1", "Notes"} {
		if !got[want] {
			t.Fatalf("missing %q in %v", want, got)
		}
	}
	if got["projects"] {
		t.Fatalf("parent duplicated with different case: %v", got)
	}
}

func TestDeleteMailboxNonEmpty(t *testing.T) {
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
	mb, err := inbox.CreateMailbox(ctx, acc.ID, "Archive", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Append(ctx, acc.ID, mb.ID, []byte("From: a@b\r\n\r\nx\r\n"), 0, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := inbox.DeleteMailbox(ctx, acc.ID, mb.ID); err != nil {
		t.Fatalf("delete non-empty: %v", err)
	}
	if _, err := inbox.ResolveMailbox(ctx, acc.ID, "Archive"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("mailbox still there: %v", err)
	}
	if msgs, err := inbox.List(ctx, acc.ID, mb.ID); err != nil || len(msgs) != 0 {
		t.Fatalf("messages left %d, err %v", len(msgs), err)
	}
	if q, err := inbox.QuotaStatus(ctx, acc.ID); err != nil || q.MessagesUsed != 0 || q.StorageUsed != 0 {
		t.Fatalf("quota not released: %+v, err %v", q, err)
	}
	if _, err := inbox.CreateMailbox(ctx, acc.ID, "Archive", true); err != nil {
		t.Fatalf("recreate: %v", err)
	}
}

func TestMailboxMessageCountAfterDeliver(t *testing.T) {
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
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\none\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\ntwo\r\n")); err != nil {
		t.Fatal(err)
	}

	st, err := inbox.Status(ctx, acc.ID, mail.InboxMailboxID, []string{"MESSAGES"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Messages != 2 {
		t.Fatalf("messages %d want 2", st.Messages)
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
	mb, err := inbox.CreateMailbox(ctx, acc.ID, "Old", true)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := inbox.RenameMailbox(ctx, acc.ID, "Old", "New")
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Name != "New" || renamed.UIDValidity <= mb.UIDValidity {
		t.Fatalf("renamed %+v", renamed)
	}
	if _, err := inbox.ResolveMailbox(ctx, acc.ID, "New"); err != nil {
		t.Fatal(err)
	}
	// RFC 3501 6.3.5: renaming INBOX moves its messages to a new folder; INBOX stays.
	if _, err := inbox.RenameMailbox(ctx, acc.ID, "INBOX", "X"); err != nil {
		t.Fatalf("rename inbox err %v", err)
	}
	if _, err := inbox.ResolveMailbox(ctx, acc.ID, "INBOX"); err != nil {
		t.Fatalf("INBOX gone after its rename: %v", err)
	}
	if _, err := inbox.CreateMailbox(ctx, acc.ID, "Taken", true); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.RenameMailbox(ctx, acc.ID, "New", "Taken"); err != mail.ErrMailboxExists {
		t.Fatalf("duplicate rename err %v", err)
	}
}
