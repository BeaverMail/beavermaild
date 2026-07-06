package pluginhost_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/pluginhost"
	"github.com/BeaverMail/beaver/internal/runtime"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestListAccountScanTargets(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := sqlite.Open(ctx, "file:"+filepath.Join(dir, "store.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	blobs := blob.NewFS(filepath.Join(dir, "blobs"))
	inbox := mail.NewInbox(store, blobs)
	d := directory.NewLocal(store)
	if _, err := directory.SeedDev(ctx, d); err != nil {
		t.Fatal(err)
	}
	acc, _, err := d.ResolveEmail(ctx, "alice@localhost")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: s@example.com\r\nTo: alice@localhost\r\nSubject: hi\r\n\r\nx\r\n")
	ref, err := inbox.ResolveMailbox(ctx, acc.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Append(ctx, acc.ID, ref.ID, raw, 0, 0); err != nil {
		t.Fatal(err)
	}

	stack := &runtime.Stack{
		Inbox: inbox,
		Blobs: blobs,
		Cfg:   config.Default(dir),
	}
	targets, cleanup, err := pluginhost.ListAccountScanTargets(ctx, stack, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(targets) != 1 {
		t.Fatalf("targets=%d", len(targets))
	}
	if targets[0].Mailbox != "INBOX" || targets[0].UID == 0 {
		t.Fatalf("target %+v", targets[0])
	}
	if _, err := os.Stat(targets[0].BodyPath); err != nil {
		t.Fatalf("blob path: %v", err)
	}
}
