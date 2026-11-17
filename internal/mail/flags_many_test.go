package mail_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
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

	res, err := inbox.SetFlagsMany(ctx, acc.ID, mail.InboxMailboxID, ids, mail.FlagFlagged, 0, []string{"$work"}, nil, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 || !res[0].Applied || !res[1].Gone || res[2].Applied || res[2].Gone {
		t.Fatalf("results %+v", res)
	}
	if res[0].Meta.Flags&mail.FlagFlagged == 0 || res[2].Meta.Flags&mail.FlagFlagged != 0 {
		t.Fatalf("flags %+v", res)
	}

	res, err = inbox.SetFlagsMany(ctx, acc.ID, mail.InboxMailboxID, []uint32{ids[0], ids[2]}, mail.FlagSeen, 0, nil, nil, mail.NoUnchangedSince)
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

// RFC 7162 3.1.3: UNCHANGEDSINCE 0 always fails. RFC 2180 4.2: a message another session moved
// elsewhere is Gone for the mailbox the caller sees, and left untouched in its new mailbox.
func TestSetFlagsManyZeroAndMoved(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/s.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	acc, err := directory.SeedDev(ctx, directory.NewLocal(store))
	if err != nil {
		t.Fatal(err)
	}
	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()))
	var ids []uint32
	for i := range 2 {
		id, err := inbox.Deliver(ctx, acc.ID, []byte("Subject: z"+strconv.Itoa(i)+"\r\n\r\nx\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	res, err := inbox.SetFlagsMany(ctx, acc.ID, mail.InboxMailboxID, ids[:1], mail.FlagSeen, 0, nil, nil, 0)
	if err != nil || res[0].Applied || res[0].Gone {
		t.Fatalf("UNCHANGEDSINCE 0: %+v %v", res, err)
	}
	if _, err := inbox.MoveMessages(ctx, acc.ID, mail.InboxMailboxID, ids[1:], mail.TrashMailboxID); err != nil {
		t.Fatal(err)
	}
	res, err = inbox.SetFlagsMany(ctx, acc.ID, mail.InboxMailboxID, ids[1:], mail.FlagFlagged, 0, nil, nil, mail.NoUnchangedSince)
	if err != nil || !res[0].Gone {
		t.Fatalf("moved message: %+v %v", res, err)
	}
	if meta, _ := inbox.GetMeta(ctx, acc.ID, ids[1]); meta.Flags&mail.FlagFlagged != 0 {
		t.Fatal("flag set on the message in its new mailbox")
	}
	// Moving it again from INBOX fails: it is no longer there (RFC 2180 4.4.1).
	if _, err := inbox.MoveMessages(ctx, acc.ID, mail.InboxMailboxID, ids[1:], mail.InboxMailboxID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("move from the wrong mailbox: %v", err)
	}
}
