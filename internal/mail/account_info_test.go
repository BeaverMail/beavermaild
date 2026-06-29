package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestListMailboxSummariesAndTree(t *testing.T) {
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
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\none")); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\ntwo")); err != nil {
		t.Fatal(err)
	}
	work, err := inbox.CreateMailbox(ctx, acc.ID, "Work")
	if err != nil {
		t.Fatal(err)
	}
	projects, err := inbox.CreateMailbox(ctx, acc.ID, "Work/Projects")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Append(ctx, acc.ID, projects.ID, []byte("From: a@b\r\n\r\np"), 0, 0); err != nil {
		t.Fatal(err)
	}
	_ = work

	summaries, err := inbox.ListMailboxSummaries(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]uint32, len(summaries))
	for _, s := range summaries {
		byName[s.Name] = s.Messages
	}
	if byName["INBOX"] != 2 {
		t.Fatalf("INBOX messages = %d, want 2", byName["INBOX"])
	}
	if byName["Work"] != 0 {
		t.Fatalf("Work messages = %d, want 0", byName["Work"])
	}
	if byName["Work/Projects"] != 1 {
		t.Fatalf("Work/Projects messages = %d, want 1", byName["Work/Projects"])
	}

	lines := mail.BuildFolderTree(summaries)
	var paths []string
	for _, line := range lines {
		paths = append(paths, line.Path)
	}
	wantPaths := []string{"INBOX", "Drafts", "Sent", "Trash", "Work", "Work/Projects"}
	if len(paths) != len(wantPaths) {
		t.Fatalf("tree paths %v", paths)
	}
	for i, want := range wantPaths {
		if paths[i] != want {
			t.Fatalf("path[%d] = %q, want %q (all %v)", i, paths[i], want, paths)
		}
	}
	for _, line := range lines {
		if line.Path == "Work/Projects" && line.Depth != 1 {
			t.Fatalf("Work/Projects depth = %d, want 1", line.Depth)
		}
	}
}
