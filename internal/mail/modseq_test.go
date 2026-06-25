package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestSetFlagsBumpsModSeq(t *testing.T) {
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
	meta, err := inbox.GetMeta(ctx, acc.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ModSeq != 1 {
		t.Fatalf("deliver modseq %d", meta.ModSeq)
	}

	if err := inbox.SetFlags(ctx, acc.ID, id, mail.FlagSeen, 0); err != nil {
		t.Fatal(err)
	}
	meta, err = inbox.GetMeta(ctx, acc.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ModSeq != 2 {
		t.Fatalf("store modseq %d", meta.ModSeq)
	}
	highest, err := inbox.HighestModSeq(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if highest != 2 {
		t.Fatalf("highest %d", highest)
	}
}

func TestSetFlagsUnchangedSince(t *testing.T) {
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
	meta, err := inbox.GetMeta(ctx, acc.ID, id)
	if err != nil {
		t.Fatal(err)
	}

	applied, _, err := inbox.SetFlagsIfUnchanged(ctx, acc.ID, id, mail.FlagSeen, 0, nil, nil, meta.ModSeq)
	if err != nil || !applied {
		t.Fatalf("apply %v err %v", applied, err)
	}
	meta, _ = inbox.GetMeta(ctx, acc.ID, id)

	applied, _, err = inbox.SetFlagsIfUnchanged(ctx, acc.ID, id, mail.FlagFlagged, 0, nil, nil, meta.ModSeq-1)
	if err != nil || applied {
		t.Fatalf("conflict apply %v err %v", applied, err)
	}
}
