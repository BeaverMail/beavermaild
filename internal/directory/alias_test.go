package directory_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
)

func TestAliases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := openDir(t)
	if _, err := d.BootstrapAdmin(ctx, "root@example.com", "secret"); err != nil {
		t.Fatal(err)
	}
	tenant, err := d.CreateTenant(ctx, "Customer", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	one, _, err := d.EnsureDomain(ctx, tenant.ID, "one.example")
	if err != nil {
		t.Fatal(err)
	}
	two, _, err := d.EnsureDomain(ctx, tenant.ID, "two.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccountRole(ctx, one.ID, "alice", "pw", directory.RoleUser); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccountRole(ctx, two.ID, "bob", "pw", directory.RoleUser); err != nil {
		t.Fatal(err)
	}

	// Targets may sit on another domain of the same tenant, never on another tenant.
	a, err := d.CreateAlias(ctx, "one.example", "Info", []string{"alice@one.example", "bob@two.example", "alice@one.example"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Email != "info@one.example" || len(a.Targets) != 2 {
		t.Fatalf("alias %+v", a)
	}
	if _, err := d.CreateAlias(ctx, "one.example", "x", []string{"root@example.com"}); err == nil {
		t.Fatal("cross-tenant target must be rejected")
	}
	if _, err := d.CreateAlias(ctx, "one.example", "x", []string{"ghost@one.example"}); err == nil {
		t.Fatal("unknown target must be rejected")
	}
	if _, err := d.CreateAlias(ctx, "one.example", "dmarc-reports", []string{"alice@one.example"}); err == nil {
		t.Fatal("reserved name must be rejected")
	}

	// Mailbox and alias names never collide.
	if _, err := d.CreateAlias(ctx, "one.example", "info", []string{"alice@one.example"}); !errors.Is(err, directory.ErrExists) {
		t.Fatalf("duplicate alias err=%v", err)
	}
	if _, err := d.CreateAlias(ctx, "one.example", "alice", []string{"bob@two.example"}); !errors.Is(err, directory.ErrExists) {
		t.Fatalf("alias over mailbox err=%v", err)
	}
	if _, err := d.CreateAccountRole(ctx, one.ID, "info", "pw", directory.RoleUser); !errors.Is(err, directory.ErrExists) {
		t.Fatalf("mailbox over alias err=%v", err)
	}

	accounts, err := d.ResolveAlias(ctx, "INFO@one.example")
	if err != nil || len(accounts) != 2 {
		t.Fatalf("resolve %+v err=%v", accounts, err)
	}
	if _, err := d.ResolveAlias(ctx, "alice@one.example"); !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("mailbox is not an alias: err=%v", err)
	}

	if a, err = d.SetAliasTargets(ctx, "info@one.example", []string{"bob@two.example"}); err != nil || len(a.Targets) != 1 {
		t.Fatalf("set targets %+v err=%v", a, err)
	}

	// A deleted target is skipped, not an error.
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	if _, err := d.DeleteAccount(ctx, "bob@two.example", blobs); err != nil {
		t.Fatal(err)
	}
	if accounts, err := d.ResolveAlias(ctx, "info@one.example"); err != nil || len(accounts) != 0 {
		t.Fatalf("deleted target %+v err=%v", accounts, err)
	}

	if err := d.DeleteAlias(ctx, "info@one.example"); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteAlias(ctx, "info@one.example"); !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("second delete err=%v", err)
	}
}
