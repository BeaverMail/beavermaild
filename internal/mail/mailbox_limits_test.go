package mail_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// Mailbox names are bounded in length and depth, and accounts in folder count: nothing used to
// limit them, and one 2000-level CREATE made every later LIST of the account take seconds.
// Not in parallel: it lowers MaxMailboxes.
func TestMailboxLimits(t *testing.T) {
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

	deepest := strings.TrimSuffix(strings.Repeat("d/", mail.MaxMailboxDepth), "/")
	longest := "L" + strings.Repeat("x", mail.MaxMailboxNameBytes-1)
	for _, name := range []string{deepest, longest} {
		if _, err := inbox.CreateMailbox(ctx, acc.ID, name, false); err != nil {
			t.Fatalf("%.20s... at the limit: %v", name, err)
		}
	}
	for _, name := range []string{deepest + "/x", longest + "x"} {
		if _, err := inbox.CreateMailbox(ctx, acc.ID, name, false); !errors.Is(err, mail.ErrMailboxLimit) {
			t.Fatalf("%.20s... past the limit: %v", name, err)
		}
	}
	if _, err := inbox.RenameMailbox(ctx, acc.ID, longest, longest+"y"); !errors.Is(err, mail.ErrMailboxLimit) {
		t.Fatalf("rename past the length limit: %v", err)
	}

	mboxes, err := inbox.ListMailboxes(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer func(n int) { mail.MaxMailboxes = n }(mail.MaxMailboxes)
	mail.MaxMailboxes = len(mboxes) + 2
	if _, err := inbox.CreateMailbox(ctx, acc.ID, "p/q", false); err != nil { // parent and child: 2
		t.Fatal(err)
	}
	if _, err := inbox.CreateMailbox(ctx, acc.ID, "r", false); !errors.Is(err, mail.ErrMailboxLimit) {
		t.Fatalf("folder past MaxMailboxes: %v", err)
	}
}

// RFC 3501 6.3.5 and 5.1.3: RENAME takes the folders under the renamed one along and creates the
// superiors of the new name; RENAME INBOX moves INBOX's messages and leaves INBOX and its children.
// Names are compared case-insensitively except inside modified UTF-7, and leading spaces count.
func TestRenameHierarchyAndNames(t *testing.T) {
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
	names := func() map[string]bool {
		mboxes, err := inbox.ListMailboxes(ctx, acc.ID)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, m := range mboxes {
			out[m.Name] = true
		}
		return out
	}

	for _, n := range []string{"a/b/c", "INBOX/kept", "&ZeVnLIqe-", " dup", "dup"} {
		if _, err := inbox.CreateMailbox(ctx, acc.ID, n, false); err != nil {
			t.Fatalf("create %q: %v", n, err)
		}
	}
	if _, err := inbox.CreateMailbox(ctx, acc.ID, "&ZEVNLIQE-", false); err != nil {
		t.Fatalf("modified UTF-7 differing only in case is another name: %v", err)
	}
	for _, bad := range []string{"caf\xc3\xa9", "bad&zzz", "bad&-x&AGE"} {
		if _, err := inbox.CreateMailbox(ctx, acc.ID, bad, false); !errors.Is(err, mail.ErrInvalidMailboxName) {
			t.Fatalf("create %q: %v", bad, err)
		}
	}

	if _, err := inbox.RenameMailbox(ctx, acc.ID, "a", "x/y"); err != nil {
		t.Fatal(err)
	}
	got := names()
	for _, n := range []string{"x", "x/y", "x/y/b", "x/y/b/c"} {
		if !got[n] {
			t.Errorf("%q missing after RENAME a x/y: %v", n, got)
		}
	}
	for _, n := range []string{"a", "a/b", "a/b/c"} {
		if got[n] {
			t.Errorf("%q left behind", n)
		}
	}
	if _, err := inbox.RenameMailbox(ctx, acc.ID, "x", "x/y/z"); !errors.Is(err, mail.ErrInvalidMailboxName) {
		t.Fatalf("rename under itself: %v", err)
	}

	if _, err := inbox.Append(ctx, acc.ID, mail.InboxMailboxID, []byte("Subject: s\r\n\r\nb\r\n"), 0, 0); err != nil {
		t.Fatal(err)
	}
	dest, err := inbox.RenameMailbox(ctx, acc.ID, "inbox", "Old")
	if err != nil {
		t.Fatal(err)
	}
	left, _ := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	moved, _ := inbox.List(ctx, acc.ID, dest.ID)
	if got := names(); len(left) != 0 || len(moved) != 1 || !got["INBOX"] || !got["INBOX/kept"] || !got["Old"] {
		t.Fatalf("RENAME INBOX: left %d moved %d names %v", len(left), len(moved), got)
	}
}
