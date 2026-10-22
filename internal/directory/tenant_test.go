package directory_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/storage/blob"
)

func TestTenantCRUD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := openDir(t)
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))

	if _, err := d.BootstrapAdmin(ctx, "root@example.com", "secret"); err != nil {
		t.Fatal(err)
	}

	t1, err := d.CreateTenant(ctx, " Acme ", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if t1.ID == directory.DefaultTenantID || t1.Name != "Acme" {
		t.Fatalf("tenant %+v", t1)
	}

	t2, err := d.CreateTenant(ctx, "Beta", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if t2.ID == t1.ID {
		t.Fatalf("duplicate ids %d", t2.ID)
	}

	if err := d.SetTenantName(ctx, t1.ID, "Acme Corp"); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetTenant(ctx, t1.ID)
	if err != nil || got.Name != "Acme Corp" {
		t.Fatalf("rename %+v err=%v", got, err)
	}

	dom, err := d.CreateDomain(ctx, t1.ID, "acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccount(ctx, dom.ID, "bob", "pw"); err != nil {
		t.Fatal(err)
	}

	_, err = d.DeleteTenant(ctx, directory.DefaultTenantID, blobs)
	if !errors.Is(err, directory.ErrForbiddenDefault) {
		t.Fatalf("default delete: %v", err)
	}

	res, err := d.DeleteTenant(ctx, t1.ID, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if res.DomainsDeleted != 1 || res.AccountsDeleted != 1 {
		t.Fatalf("cascade %+v", res)
	}
	if _, err := d.GetTenant(ctx, t1.ID); !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("tenant still exists: %v", err)
	}
	if _, err := d.LookupDomain(ctx, "acme.test"); !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("domain still exists: %v", err)
	}
}

func TestTenantExternalIDUnique(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := openDir(t)
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	if _, err := d.BootstrapAdmin(ctx, "root@example.com", "secret"); err != nil {
		t.Fatal(err)
	}

	if _, err := d.CreateTenant(ctx, "Bad", "has space", 0); err == nil {
		t.Fatal("external_id with space must be rejected")
	}

	// Concurrent creates with one external_id: exactly one wins, the rest get ErrExists.
	const n = 8
	errs := make(chan error, n)
	for range n {
		go func() {
			_, err := d.CreateTenant(ctx, "Acme", "cust-42", 0)
			errs <- err
		}()
	}
	var created int
	for range n {
		switch err := <-errs; {
		case err == nil:
			created++
		case !errors.Is(err, directory.ErrExists):
			t.Fatalf("create err=%v", err)
		}
	}
	if created != 1 {
		t.Fatalf("created %d tenants, want 1", created)
	}

	got, err := d.TenantByExternalID(ctx, "cust-42")
	if err != nil || got.Name != "Acme" || got.ExternalID != "cust-42" {
		t.Fatalf("lookup %+v err=%v", got, err)
	}
	if _, err := d.DeleteTenant(ctx, got.ID, blobs); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateTenant(ctx, "Acme again", "cust-42", 0); err != nil {
		t.Fatalf("external_id must be reusable after delete: %v", err)
	}
}

// login_disabled on the domain or tenant blocks login (after the password check) but keeps the
// account resolvable, so inbound mail is still accepted.
func TestLoginDisabled(t *testing.T) {
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
	dom, _, err := d.EnsureDomain(ctx, tenant.ID, "customer.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccountRole(ctx, dom.ID, "alice", "pw", directory.RoleUser); err != nil {
		t.Fatal(err)
	}
	const email = "alice@customer.example"

	if _, err := d.SetDomainLoginDisabled(ctx, "customer.example", true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Authenticate(ctx, email, "pw"); !errors.Is(err, directory.ErrInactive) {
		t.Fatalf("domain disabled: err=%v", err)
	}
	if _, err := d.Authenticate(ctx, email, "wrong"); !errors.Is(err, directory.ErrInvalidCredentials) {
		t.Fatalf("wrong password must not reveal suspension: err=%v", err)
	}
	if _, _, err := d.ResolveEmail(ctx, email); err != nil {
		t.Fatalf("delivery lookup must still work: %v", err)
	}
	if _, err := d.SetDomainLoginDisabled(ctx, "customer.example", false); err != nil {
		t.Fatal(err)
	}

	if err := d.SetTenantLoginDisabled(ctx, tenant.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Authenticate(ctx, email, "pw"); !errors.Is(err, directory.ErrInactive) {
		t.Fatalf("tenant disabled: err=%v", err)
	}
	if err := d.SetTenantLoginDisabled(ctx, tenant.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Authenticate(ctx, email, "pw"); err != nil {
		t.Fatalf("restored: %v", err)
	}

	if err := d.SetTenantLoginDisabled(ctx, directory.DefaultTenantID, true); err == nil {
		t.Fatal("default tenant must not be disabled")
	}
}
