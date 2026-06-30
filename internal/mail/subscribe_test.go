package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestMailboxSubscribe(t *testing.T) {
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

	created, err := inbox.CreateMailbox(ctx, acc.ID, "Work")
	if err != nil {
		t.Fatal(err)
	}
	if !created.Subscribed {
		t.Fatal("new folder should start subscribed")
	}

	mboxes, err := inbox.ListMailboxes(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	var workSubscribed bool
	for _, mb := range mboxes {
		if mb.Name == "Work" {
			workSubscribed = mb.Subscribed
		}
		if mb.Name == "INBOX" && !mb.Subscribed {
			t.Fatal("inbox should be subscribed")
		}
	}
	if !workSubscribed {
		t.Fatal("work should be subscribed")
	}

	if err := inbox.SetMailboxSubscribed(ctx, acc.ID, "Work", true); err != nil {
		t.Fatal(err)
	}
	work, err := inbox.ResolveMailbox(ctx, acc.ID, "Work")
	if err != nil || !work.Subscribed {
		t.Fatalf("subscribe work: %+v err=%v", work, err)
	}

	if err := inbox.SetMailboxSubscribed(ctx, acc.ID, "INBOX", false); err != nil {
		t.Fatal(err)
	}
	inb, err := inbox.ResolveMailbox(ctx, acc.ID, "INBOX")
	if err != nil || inb.Subscribed {
		t.Fatalf("unsubscribe inbox: %+v err=%v", inb, err)
	}
}
