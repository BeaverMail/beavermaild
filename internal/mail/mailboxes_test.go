package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

func TestEnsureMailboxesAddsSentTrash(t *testing.T) {
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
	mboxes, err := inbox.ListMailboxes(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(mboxes) != 4 {
		t.Fatalf("mailboxes %d", len(mboxes))
	}
	sent, err := inbox.ResolveMailbox(ctx, acc.ID, "Sent")
	if err != nil {
		t.Fatal(err)
	}
	if sent.ID != mail.SentMailboxID {
		t.Fatalf("sent id %d", sent.ID)
	}
}

func TestMatchSearchSeen(t *testing.T) {
	t.Parallel()
	seen := true
	unseen := false
	msgs := []mail.Message{
		{UID: 1},
		{UID: 2},
	}
	msgs[1].Meta.Flags = mail.FlagSeen

	all := mail.MatchSearch(msgs, mail.SearchCriteria{All: true})
	if len(all) != 2 {
		t.Fatalf("all %v", all)
	}
	seenOnly := mail.MatchSearch(msgs, mail.SearchCriteria{Seen: &seen})
	if len(seenOnly) != 1 || seenOnly[0] != 2 {
		t.Fatalf("seen %v", seenOnly)
	}
	unseenOnly := mail.MatchSearch(msgs, mail.SearchCriteria{Seen: &unseen})
	if len(unseenOnly) != 1 || unseenOnly[0] != 1 {
		t.Fatalf("unseen %v", unseenOnly)
	}
}
