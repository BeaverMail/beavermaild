package directory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
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
