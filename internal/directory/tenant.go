// Tenant create, rename, and delete for the local directory.
package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
)

// DeleteTenantResult reports cascade removals for a tenant wipe.
type DeleteTenantResult struct {
	Tenant          storage.Tenant
	DomainsDeleted  int
	AccountsDeleted int
}

// CreateTenant allocates a new tenant id and stores name.
func (d *Local) CreateTenant(ctx context.Context, name string) (storage.Tenant, error) {
	name, err := validateTenantName(name)
	if err != nil {
		return storage.Tenant{}, err
	}
	id, err := d.allocTenantID(ctx)
	if err != nil {
		return storage.Tenant{}, err
	}
	tenant := storage.Tenant{ID: id, Name: name}
	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := d.putTenant(batch, tenant); err != nil {
		return storage.Tenant{}, err
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		return storage.Tenant{}, err
	}
	return tenant, nil
}

// SetTenantName renames an existing tenant.
func (d *Local) SetTenantName(ctx context.Context, id uint32, name string) error {
	name, err := validateTenantName(name)
	if err != nil {
		return err
	}
	tenant, err := d.GetTenant(ctx, id)
	if err != nil {
		return err
	}
	tenant.Name = name
	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := d.putTenant(batch, tenant); err != nil {
		return err
	}
	return d.store.Commit(ctx, batch)
}

// DeleteTenant removes a tenant after cascading DeleteDomain on all its domains.
// The default tenant (id=1) cannot be deleted.
func (d *Local) DeleteTenant(ctx context.Context, id uint32, blobs *blob.FS) (DeleteTenantResult, error) {
	if id == 0 {
		return DeleteTenantResult{}, fmt.Errorf("directory: tenant_id required")
	}
	if id == DefaultTenantID {
		return DeleteTenantResult{}, ErrForbiddenDefault
	}
	if blobs == nil {
		return DeleteTenantResult{}, fmt.Errorf("directory: blob store required")
	}
	tenant, err := d.GetTenant(ctx, id)
	if err != nil {
		return DeleteTenantResult{}, err
	}
	domains, err := d.ListDomains(ctx)
	if err != nil {
		return DeleteTenantResult{}, err
	}
	var domainsDeleted, accountsDeleted int
	for _, dom := range domains {
		if dom.TenantID != id {
			continue
		}
		res, err := d.DeleteDomain(ctx, dom.Name, blobs)
		if err != nil {
			return DeleteTenantResult{}, err
		}
		domainsDeleted++
		accountsDeleted += res.AccountsDeleted
	}
	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := batch.Delete(storage.SubspaceAccount, storage.BatchSuffix(colTenant, id, nil)); err != nil {
		return DeleteTenantResult{}, err
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		return DeleteTenantResult{}, err
	}
	return DeleteTenantResult{
		Tenant:          tenant,
		DomainsDeleted:  domainsDeleted,
		AccountsDeleted: accountsDeleted,
	}, nil
}

func (d *Local) allocTenantID(ctx context.Context) (uint32, error) {
	for range 64 {
		id, err := d.nextID(ctx, "tenant")
		if err != nil {
			return 0, err
		}
		_, err = d.GetTenant(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return id, nil
		}
		if err != nil {
			return 0, err
		}
	}
	return 0, fmt.Errorf("directory: could not allocate tenant id")
}

func validateTenantName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("directory: empty tenant name")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("directory: invalid tenant name")
		}
	}
	if len(name) > 128 {
		return "", fmt.Errorf("directory: tenant name too long")
	}
	return name, nil
}
