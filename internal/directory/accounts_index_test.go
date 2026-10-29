package directory

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// A store written before the domain → account index existed is backfilled on first read,
// and later creates/deletes keep the index exact.
func TestDomainAccountIndexBackfill(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	old := NewLocal(store)
	one, _, err := old.EnsureDomain(ctx, DefaultTenantID, "one.example")
	if err != nil {
		t.Fatal(err)
	}
	two, _, err := old.EnsureDomain(ctx, DefaultTenantID, "two.example")
	if err != nil {
		t.Fatal(err)
	}
	a, err := old.CreateAccountRole(ctx, one.ID, "alice", "pw", RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	b, err := old.CreateAccountRole(ctx, two.ID, "bob", "pw", RoleUser)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a pre-index store: drop the index rows and the marker.
	batch := storage.NewBatch().WithAccount(systemAccountID)
	for _, k := range [][]byte{daccKey(one.ID, a.ID), daccKey(two.ID, b.ID), []byte("meta/" + daccMarker)} {
		if err := batch.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, k)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Commit(ctx, batch); err != nil {
		t.Fatal(err)
	}

	d := NewLocal(store)
	accounts, _, err := d.ListAccounts(ctx, "one.example")
	if err != nil || len(accounts) != 1 || accounts[0].ID != a.ID {
		t.Fatalf("after backfill %+v err=%v", accounts, err)
	}

	c, err := d.CreateAccountRole(ctx, one.ID, "carol", "pw", RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := d.TenantAccountIDs(ctx, DefaultTenantID)
	slices.Sort(ids)
	if err != nil || !slices.Equal(ids, []uint32{a.ID, b.ID, c.ID}) {
		t.Fatalf("tenant ids %v err=%v", ids, err)
	}

	if _, err := d.DeleteAccount(ctx, "alice@one.example", blob.NewFS(filepath.Join(t.TempDir(), "blobs"))); err != nil {
		t.Fatal(err)
	}
	accounts, _, err = d.ListAccounts(ctx, "one.example")
	if err != nil || len(accounts) != 1 || accounts[0].ID != c.ID {
		t.Fatalf("after delete %+v err=%v", accounts, err)
	}
}

// Report addresses are taken on every domain: creating a mailbox with that name must fail clearly.
func TestReservedReportLocalParts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d := NewLocal(store)
	dom, _, err := d.EnsureDomain(ctx, DefaultTenantID, "one.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, lp := range []string{"dmarc-reports", "TLS-Reports"} {
		if _, err := d.CreateAccountRole(ctx, dom.ID, lp, "pw", RoleUser); err == nil {
			t.Fatalf("%s must be reserved", lp)
		}
	}
}

// Deleting a domain removes its alias rows (keyed by the old domain id).
func TestDeleteDomainRemovesAliases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d := NewLocal(store)
	dom, _, err := d.EnsureDomain(ctx, DefaultTenantID, "one.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccountRole(ctx, dom.ID, "alice", "pw", RoleUser); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAlias(ctx, "one.example", "sales", []string{"alice@one.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DeleteDomain(ctx, "one.example", blob.NewFS(filepath.Join(t.TempDir(), "blobs"))); err != nil {
		t.Fatal(err)
	}
	if left, err := d.domainAliases(ctx, dom.ID); err != nil || len(left) != 0 {
		t.Fatalf("alias rows left %+v err=%v", left, err)
	}
}
