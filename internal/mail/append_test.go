package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestAppendToDrafts(t *testing.T) {
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
	drafts, err := inbox.ResolveMailbox(ctx, acc.ID, "Drafts")
	if err != nil {
		t.Fatal(err)
	}

	raw := []byte("From: a@b\r\nSubject: draft\r\n\r\nbody\r\n")
	wantDate := int64(1719313800) // 25-Jun-2024 10:30:00 UTC
	id, err := inbox.Append(ctx, acc.ID, drafts.ID, raw, mail.FlagDraft, wantDate)
	if err != nil {
		t.Fatal(err)
	}

	msgs, err := inbox.List(ctx, acc.ID, drafts.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].UID != id {
		t.Fatalf("msgs %+v id %d", msgs, id)
	}
	if msgs[0].Meta.Flags&mail.FlagDraft == 0 {
		t.Fatalf("flags %#x", msgs[0].Meta.Flags)
	}
	if msgs[0].Meta.ReceivedAt != wantDate {
		t.Fatalf("receivedAt %d want %d", msgs[0].Meta.ReceivedAt, wantDate)
	}
}
