// Domain lookup, listing, and validation for the local directory.
package directory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/BeaverMail/beaver/internal/storage"
)

// DefaultTenantID is the bootstrap tenant for single-tenant installs.
const DefaultTenantID uint32 = 1

// LookupDomain returns a registered mail domain by name.
func (d *Local) LookupDomain(ctx context.Context, name string) (storage.Domain, error) {
	name = normalizeDomain(name)
	if name == "" {
		return storage.Domain{}, fmt.Errorf("directory: empty domain")
	}
	id, err := d.lookupDomainID(ctx, name)
	if err != nil {
		return storage.Domain{}, err
	}
	return d.getDomain(ctx, id)
}

// ListDomains returns all registered domains sorted by name.
func (d *Local) ListDomains(ctx context.Context) ([]storage.Domain, error) {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceAccount, systemAccountID, 0, colDomain, 6)
	to := storage.AppendKey(nil, storage.SubspaceAccount, systemAccountID, ^uint32(0), colDomain, nil)

	var out []storage.Domain
	err := d.store.Iterate(ctx, from, to, func(_, v []byte) error {
		var dom storage.Domain
		if err := storage.UnmarshalPersist(v, &dom); err != nil {
			return err
		}
		out = append(out, dom)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b storage.Domain) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// EnsureDomain creates the domain or returns the existing record (idempotent).
func (d *Local) EnsureDomain(ctx context.Context, tenantID uint32, name string) (storage.Domain, bool, error) {
	name, err := validateDomainName(name)
	if err != nil {
		return storage.Domain{}, false, err
	}
	if err := d.ensureTenant(ctx, tenantRecord(tenantID)); err != nil {
		return storage.Domain{}, false, err
	}
	dom, err := d.CreateDomain(ctx, tenantID, name)
	if err == nil {
		return dom, true, nil
	}
	if !errors.Is(err, ErrExists) {
		return storage.Domain{}, false, err
	}
	existing, err := d.LookupDomain(ctx, name)
	if err != nil {
		return storage.Domain{}, false, err
	}
	return existing, false, nil
}

func tenantRecord(id uint32) storage.Tenant {
	name := fmt.Sprintf("tenant-%d", id)
	if id == DefaultTenantID {
		name = "default"
	}
	return storage.Tenant{ID: id, Name: name}
}

func validateDomainName(name string) (string, error) {
	name = normalizeDomain(name)
	if name == "" {
		return "", fmt.Errorf("directory: empty domain")
	}
	for _, r := range name {
		if r <= unicode.MaxASCII && (r < 0x21 || r == '/' || r == '@') {
			return "", fmt.Errorf("directory: invalid domain %q", name)
		}
		if r == ' ' || unicode.IsControl(r) {
			return "", fmt.Errorf("directory: invalid domain %q", name)
		}
	}
	if name != "localhost" && !strings.Contains(name, ".") {
		return "", fmt.Errorf("directory: invalid domain %q", name)
	}
	return name, nil
}
