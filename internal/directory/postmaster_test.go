package directory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
)

func TestResolvePostmaster(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := openDir(t)
	if _, err := d.ResolvePostmaster(ctx, 0); !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("empty directory: %v, want ErrNotFound", err)
	}
	root, err := d.BootstrapAdmin(ctx, "root@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := d.CreateTenant(ctx, "Customer", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	dom, _, err := d.EnsureDomain(ctx, tenant.ID, "one.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccountRole(ctx, dom.ID, "alice", "pw", directory.RoleUser); err != nil {
		t.Fatal(err)
	}
	only := func(tenantID, want uint32) {
		t.Helper()
		got, err := d.ResolvePostmaster(ctx, tenantID)
		if err != nil || len(got) != 1 || got[0].ID != want {
			t.Fatalf("tenant %d: %+v, %v, want account %d", tenantID, got, err, want)
		}
	}
	// No tenant admin yet: the instance admin reads it.
	only(tenant.ID, root.ID)
	boss, err := d.CreateAccountRole(ctx, dom.ID, "boss", "pw", directory.RoleTenantAdmin)
	if err != nil {
		t.Fatal(err)
	}
	only(tenant.ID, boss.ID)
	// Bare <Postmaster> (tenant 0) always goes to the instance admins.
	only(0, root.ID)
}
