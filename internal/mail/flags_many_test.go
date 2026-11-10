package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// TestSetFlagsMany checks a batched STORE: results follow the input, an expunged message is Gone,
// UNCHANGEDSINCE refuses only newer messages, each change gets its own MODSEQ, and the mailbox
// HIGHESTMODSEQ follows.
func TestSetFlagsMany(t *testing.T) {
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
		id, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nm"+string(rune('0'+i))+"\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := inbox.DeleteMessage(ctx, acc.ID, ids[1]); err != nil {
		t.Fatal(err)
	}
	// Make ids[2] newer than the UNCHANGEDSINCE value used below.
	if err := inbox.SetFlags(ctx, acc.ID, ids[2], mail.FlagAnswered, 0); err != nil {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	since := min(msgs[0].Meta.ModSeq, msgs[1].Meta.ModSeq) // ids[0] passes, ids[2] is newer

	res, err := inbox.SetFlagsMany(ctx, acc.ID, ids, mail.FlagFlagged, 0, []string{"$work"}, nil, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 || !res[0].Applied || !res[1].Gone || res[2].Applied || res[2].Gone {
		t.Fatalf("results %+v", res)
	}
	if res[0].Meta.Flags&mail.FlagFlagged == 0 || res[2].Meta.Flags&mail.FlagFlagged != 0 {
		t.Fatalf("flags %+v", res)
	}

	res, err = inbox.SetFlagsMany(ctx, acc.ID, []uint32{ids[0], ids[2]}, mail.FlagSeen, 0, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Meta.ModSeq == res[1].Meta.ModSeq {
		t.Fatalf("shared MODSEQ %d", res[0].Meta.ModSeq)
	}
	highest, err := inbox.HighestModSeq(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if want := max(res[0].Meta.ModSeq, res[1].Meta.ModSeq); highest != want {
		t.Fatalf("HIGHESTMODSEQ %d, want %d", highest, want)
	}
}
