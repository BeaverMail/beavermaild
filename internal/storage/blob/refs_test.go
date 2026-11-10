package blob_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// TestGCKeepsReferencedAndRemovesOrphans checks GC: a blob shared by two messages survives the
// deletion of one, goes once both are deleted, and a fresh orphan is kept for the grace period.
func TestGCKeepsReferencedAndRemovesOrphans(t *testing.T) {
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
	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	id, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nx\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, copies, err := inbox.CopyMessages(ctx, acc.ID, []uint32{id}, mail.SentMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	path := blobs.Path(msgs[0].Meta.BlobHash)
	gc := func(grace time.Duration) int {
		t.Helper()
		n, err := blob.GC(ctx, store, blobs, grace)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	exists := func() bool {
		_, err := os.Stat(path)
		return err == nil
	}

	if err := inbox.DeleteMessage(ctx, acc.ID, id); err != nil {
		t.Fatal(err)
	}
	if gc(0); !exists() {
		t.Fatal("GC removed a blob still used by the copy")
	}
	sent, err := inbox.List(ctx, acc.ID, mail.SentMailboxID)
	if err != nil || len(sent) != 1 || len(copies) != 1 {
		t.Fatalf("copy: %v %d", err, len(sent))
	}
	if err := inbox.DeleteMessage(ctx, acc.ID, sent[0].StorageID()); err != nil {
		t.Fatal(err)
	}
	if !exists() {
		t.Fatal("DeleteMessage removed the blob itself")
	}
	if gc(time.Hour); !exists() {
		t.Fatal("GC removed an orphan younger than the grace period")
	}
	if n := gc(0); n != 1 || exists() {
		t.Fatalf("GC removed %d, blob exists=%v", n, exists())
	}
}

// TestGCRemovesStaleTempFiles checks GC drops temp files an interrupted Put left behind.
func TestGCRemovesStaleTempFiles(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	root := t.TempDir() + "/blobs"
	if err := os.MkdirAll(filepath.Join(root, "ab"), 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(root, "ab", "put-123")
	if err := os.WriteFile(tmp, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(tmp, old, old); err != nil {
		t.Fatal(err)
	}
	if n, err := blob.GC(ctx, store, blob.NewFS(root), time.Hour); err != nil || n != 1 {
		t.Fatalf("GC removed %d, err %v", n, err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("stale temp file still there")
	}
}

// TestPutTouchesReusedBlob checks Put refreshes the mtime of a blob it reuses, so GC keeps it
// while the new message referencing it is being stored.
func TestPutTouchesReusedBlob(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fs := blob.NewFS(t.TempDir() + "/blobs")
	hash, err := fs.Put(ctx, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(fs.Path(hash), old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Put(ctx, []byte("same")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fs.Path(hash))
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(info.ModTime()) > time.Minute {
		t.Fatalf("mtime not refreshed: %v", info.ModTime())
	}
}
