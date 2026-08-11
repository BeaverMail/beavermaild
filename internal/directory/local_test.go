package directory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestLocalCreateAndAuthenticate(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	ctx := context.Background()

	if _, err := d.CreateDomain(ctx, 1, "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccount(ctx, 1, "bob", "secret"); err != nil {
		t.Fatal(err)
	}

	p, err := d.Authenticate(ctx, "bob@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if p.Email() != "bob@example.com" {
		t.Fatalf("email %q", p.Email())
	}

	_, err = d.Authenticate(ctx, "bob@example.com", "wrong")
	if !errors.Is(err, directory.ErrInvalidCredentials) {
		t.Fatalf("got %v", err)
	}
}

func TestLocalResolveEmail(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	ctx := context.Background()

	_, err := d.CreateDomain(ctx, 1, "test.local")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.CreateAccount(ctx, 1, "a", "pw")
	if err != nil {
		t.Fatal(err)
	}

	acc, dom, err := d.ResolveEmail(ctx, "a@test.local")
	if err != nil {
		t.Fatal(err)
	}
	if acc.LocalPart != "a" || dom.Name != "test.local" {
		t.Fatalf("acc %+v dom %+v", acc, dom)
	}
}

func TestSeedDevIdempotent(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	ctx := context.Background()

	acc1, err := directory.SeedDev(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	acc2, err := directory.SeedDev(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if acc1.ID != acc2.ID {
		t.Fatalf("ids %d %d", acc1.ID, acc2.ID)
	}

	p, err := d.Authenticate(ctx, "alice@localhost", directory.SeedPassword())
	if err != nil {
		t.Fatal(err)
	}
	if p.LocalPart != "alice" {
		t.Fatalf("principal %+v", p)
	}
	if p.Role != directory.RoleAdmin {
		t.Fatalf("seed role %q want admin", p.Role)
	}
}

func TestSeedDevPromotesLegacyUserToAdmin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := openDir(t)
	dom, _, err := d.EnsureDomain(ctx, directory.DefaultTenantID, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccount(ctx, dom.ID, "alice", directory.SeedPassword()); err != nil {
		t.Fatal(err)
	}
	acc, err := directory.SeedDev(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if directory.NormalizeRole(acc.Role) != directory.RoleAdmin {
		t.Fatalf("role %q", acc.Role)
	}
}

func openDir(t *testing.T) *directory.Local {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return directory.NewLocal(store)
}
