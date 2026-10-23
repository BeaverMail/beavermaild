package directory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
)

func TestNeedsSetupAndBootstrapAdmin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := openDir(t)

	needed, err := d.NeedsSetup(ctx)
	if err != nil || !needed {
		t.Fatalf("empty NeedsSetup=%v err=%v", needed, err)
	}

	acc, err := d.BootstrapAdmin(ctx, "root@mail.example.com", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if directory.NormalizeRole(acc.Role) != directory.RoleAdmin {
		t.Fatalf("role %q", acc.Role)
	}
	if acc.TenantID != directory.DefaultTenantID {
		t.Fatalf("tenant %d", acc.TenantID)
	}

	needed, err = d.NeedsSetup(ctx)
	if err != nil || needed {
		t.Fatalf("after bootstrap NeedsSetup=%v err=%v", needed, err)
	}

	_, err = d.BootstrapAdmin(ctx, "other@mail.example.com", "s3cret")
	if !errors.Is(err, directory.ErrSetupComplete) {
		t.Fatalf("second bootstrap: %v", err)
	}

	p, err := d.Authenticate(ctx, "root@mail.example.com", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if p.Role != directory.RoleAdmin || p.DomainName != "mail.example.com" {
		t.Fatalf("principal %+v", p)
	}
}

func TestSetPasswordAndSetActive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := openDir(t)

	acc, err := d.BootstrapAdmin(ctx, "ops@example.com", "first")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetPassword(ctx, acc.ID, "second"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Authenticate(ctx, "ops@example.com", "first"); !errors.Is(err, directory.ErrInvalidCredentials) {
		t.Fatalf("old password: %v", err)
	}
	if _, err := d.Authenticate(ctx, "ops@example.com", "second"); err != nil {
		t.Fatal(err)
	}

	if err := d.SetActive(ctx, acc.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Authenticate(ctx, "ops@example.com", "second"); !errors.Is(err, directory.ErrInactive) {
		t.Fatalf("inactive: %v", err)
	}
	if err := d.SetActive(ctx, acc.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Authenticate(ctx, "ops@example.com", "second"); err != nil {
		t.Fatal(err)
	}
}

func TestNeedsSetupClosedByAPIKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := openDir(t)
	if _, _, err := d.CreateAPIKey(ctx, "panel", directory.RoleProvisioner); err != nil {
		t.Fatal(err)
	}
	needed, err := d.NeedsSetup(ctx)
	if err != nil || needed {
		t.Fatalf("with an API key NeedsSetup=%v err=%v", needed, err)
	}
	if _, err := d.BootstrapAdmin(ctx, "root@mail.example.com", "s3cret"); !errors.Is(err, directory.ErrSetupComplete) {
		t.Fatalf("bootstrap with an API key: %v", err)
	}
}
