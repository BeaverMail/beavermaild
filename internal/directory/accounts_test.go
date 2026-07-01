package directory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
)

func TestListAccounts(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	ctx := context.Background()

	dom, _, err := d.EnsureDomain(ctx, directory.DefaultTenantID, "accounts.test")
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := d.ListAccounts(ctx, "accounts.test"); err != nil {
		t.Fatal(err)
	}

	for _, local := range []string{"zeta", "alpha"} {
		if _, err := d.CreateAccount(ctx, dom.ID, local, "secret"); err != nil {
			t.Fatal(err)
		}
	}

	list, gotDom, err := d.ListAccounts(ctx, "accounts.test")
	if err != nil {
		t.Fatal(err)
	}
	if gotDom.ID != dom.ID {
		t.Fatalf("domain id %d want %d", gotDom.ID, dom.ID)
	}
	if len(list) != 2 {
		t.Fatalf("len %d", len(list))
	}
	if list[0].LocalPart != "alpha" || list[1].LocalPart != "zeta" {
		t.Fatalf("order %+v", list)
	}

	_, _, err = d.ListAccounts(ctx, "missing.test")
	if !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}
