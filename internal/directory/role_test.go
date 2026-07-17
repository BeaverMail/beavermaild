package directory_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestCreateAccountRoleAndTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d := directory.NewLocal(store)

	dom, _, err := d.EnsureDomain(ctx, directory.DefaultTenantID, "role.test")
	if err != nil {
		t.Fatal(err)
	}
	if dom.TenantID != directory.DefaultTenantID {
		t.Fatalf("domain tenant %d", dom.TenantID)
	}

	user, err := d.CreateAccount(ctx, dom.ID, "bob", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != directory.RoleUser || user.TenantID != directory.DefaultTenantID {
		t.Fatalf("user %+v", user)
	}

	admin, err := d.CreateAccountRole(ctx, dom.ID, "root", "secret", directory.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if admin.Role != directory.RoleAdmin {
		t.Fatalf("admin role %q", admin.Role)
	}

	p, err := d.Authenticate(ctx, "root@role.test", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if p.Role != directory.RoleAdmin || p.TenantID != directory.DefaultTenantID {
		t.Fatalf("principal %+v", p)
	}
}

func TestCreateDomainRequiresTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d := directory.NewLocal(store)
	if _, err := d.CreateDomain(ctx, 0, "bad.test"); err == nil {
		t.Fatal("expected tenant_id required")
	}
}

func TestSeedDevMakesAdmin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d := directory.NewLocal(store)
	acc, err := directory.SeedDev(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if acc.Role != directory.RoleAdmin || acc.TenantID != directory.DefaultTenantID {
		t.Fatalf("seed %+v", acc)
	}
	tenants, err := d.ListTenants(ctx)
	if err != nil || len(tenants) != 1 || tenants[0].ID != directory.DefaultTenantID {
		t.Fatalf("tenants %+v err=%v", tenants, err)
	}
}

func TestValidateRole(t *testing.T) {
	t.Parallel()
	if err := directory.ValidateRole("nope"); err == nil {
		t.Fatal("expected error")
	}
	if directory.NormalizeRole("") != directory.RoleUser {
		t.Fatal("empty -> user")
	}
}
