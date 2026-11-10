package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
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

	created, err := inbox.CreateMailbox(ctx, acc.ID, "Work", true)
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

// TestSubscriptionOutlivesMailbox checks RFC 3501 subscriptions: CREATE with subscribe=false does
// not subscribe, an explicit subscription survives DELETE, comes back with CREATE, and UNSUBSCRIBE
// drops it.
func TestSubscriptionOutlivesMailbox(t *testing.T) {
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
	orphans := func() []string {
		t.Helper()
		subs, err := inbox.ListOrphanSubscriptions(ctx, acc.ID)
		if err != nil {
			t.Fatal(err)
		}
		return subs
	}

	mb, err := inbox.CreateMailbox(ctx, acc.ID, "Work", false)
	if err != nil {
		t.Fatal(err)
	}
	if mb.Subscribed {
		t.Fatal("CREATE subscribed")
	}
	if err := inbox.SetMailboxSubscribed(ctx, acc.ID, "Work", true); err != nil {
		t.Fatal(err)
	}
	if err := inbox.DeleteMailbox(ctx, acc.ID, mb.ID); err != nil {
		t.Fatal(err)
	}
	if got := orphans(); len(got) != 1 || got[0] != "Work" {
		t.Fatalf("after delete: %q", got)
	}
	again, err := inbox.CreateMailbox(ctx, acc.ID, "Work", false)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Subscribed || len(orphans()) != 0 {
		t.Fatalf("recreate: subscribed=%v orphans=%q", again.Subscribed, orphans())
	}
	if err := inbox.DeleteMailbox(ctx, acc.ID, again.ID); err != nil {
		t.Fatal(err)
	}
	if err := inbox.SetMailboxSubscribed(ctx, acc.ID, "Work", false); err != nil {
		t.Fatal(err)
	}
	if got := orphans(); len(got) != 0 {
		t.Fatalf("after unsubscribe: %q", got)
	}
	// A folder never subscribed leaves nothing behind.
	other, err := inbox.CreateMailbox(ctx, acc.ID, "Other", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.DeleteMailbox(ctx, acc.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	if got := orphans(); len(got) != 0 {
		t.Fatalf("unsubscribed folder left %q", got)
	}
}
