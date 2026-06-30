package directory_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestCreateDomainRejectsInvalid(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	ctx := context.Background()

	for _, in := range []string{"pippo", "", "bad@host", "sp ace.com"} {
		if _, err := d.CreateDomain(ctx, directory.DefaultTenantID, in); err == nil {
			t.Fatalf("%q: want error", in)
		}
	}
}

func TestLookupDomain(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	ctx := context.Background()

	dom, _, err := d.EnsureDomain(ctx, directory.DefaultTenantID, "lookup.test")
	if err != nil {
		t.Fatal(err)
	}

	got, err := d.LookupDomain(ctx, "lookup.test")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != dom.ID {
		t.Fatalf("id %d want %d", got.ID, dom.ID)
	}

	_, err = d.LookupDomain(ctx, "missing.test")
	if !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestListDomains(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	ctx := context.Background()

	if _, err := d.ListDomains(ctx); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"zeta.test", "alpha.test"} {
		if _, _, err := d.EnsureDomain(ctx, directory.DefaultTenantID, name); err != nil {
			t.Fatal(err)
		}
	}

	list, err := d.ListDomains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("len %d", len(list))
	}
	if list[0].Name != "alpha.test" || list[1].Name != "zeta.test" {
		t.Fatalf("order %+v", list)
	}
}

func TestEnsureDomainIdempotent(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	ctx := context.Background()

	d1, created, err := d.EnsureDomain(ctx, directory.DefaultTenantID, "idem.test")
	if err != nil || !created {
		t.Fatalf("first: dom=%+v created=%v err=%v", d1, created, err)
	}
	d2, created, err := d.EnsureDomain(ctx, directory.DefaultTenantID, "idem.test")
	if err != nil || created {
		t.Fatalf("second: dom=%+v created=%v err=%v", d2, created, err)
	}
	if d1.ID != d2.ID {
		t.Fatalf("ids %d %d", d1.ID, d2.ID)
	}
}

func TestCreateDomainNormalizesCase(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	ctx := context.Background()

	dom, err := d.CreateDomain(ctx, directory.DefaultTenantID, "EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	if dom.Name != "example.com" {
		t.Fatalf("name %q", dom.Name)
	}
}

func TestDeleteDomainRemovesAccountsAndMail(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	d := directory.NewLocal(store)
	dom, _, err := d.EnsureDomain(ctx, directory.DefaultTenantID, "gone.test")
	if err != nil {
		t.Fatal(err)
	}
	acc, err := d.CreateAccount(ctx, dom.ID, "bob", "secret")
	if err != nil {
		t.Fatal(err)
	}

	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || !msgs[0].Meta.HasBlob() {
		t.Fatalf("messages %+v", msgs)
	}
	blobPath := inbox.Blobs().Path(msgs[0].Meta.BlobHash)

	res, err := d.DeleteDomain(ctx, "gone.test", inbox.Blobs())
	if err != nil {
		t.Fatal(err)
	}
	if res.AccountsDeleted != 1 || res.Domain.Name != "gone.test" {
		t.Fatalf("result %+v", res)
	}

	_, err = d.LookupDomain(ctx, "gone.test")
	if !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("domain still exists: %v", err)
	}
	_, _, err = d.ResolveEmail(ctx, "bob@gone.test")
	if !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("account still exists: %v", err)
	}

	msgs, err = inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("mail left behind: %d messages", len(msgs))
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatalf("blob still on disk: %v", err)
	}
}

func TestDeleteDomainNotFound(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	blobs := blob.NewFS(t.TempDir() + "/blobs")
	_, err := d.DeleteDomain(context.Background(), "missing.test", blobs)
	if !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}
