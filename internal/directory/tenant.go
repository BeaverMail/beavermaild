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

// tenantExtLookup is the lookup kind mapping external_id to tenant id.
const tenantExtLookup = "tenant-ext"

// CreateTenant allocates a new tenant id and stores name. A non-empty externalID must be unique:
// a repeat returns ErrExists atomically, so retried creates never duplicate a tenant.
// storageLimit is the tenant-wide mailbox storage cap (0 = unlimited).
func (d *Local) CreateTenant(ctx context.Context, name, externalID string, storageLimit uint64) (storage.Tenant, error) {
	name, err := validateTenantName(name)
	if err != nil {
		return storage.Tenant{}, err
	}
	externalID, err = validateTenantExternalID(externalID)
	if err != nil {
		return storage.Tenant{}, err
	}
	if externalID != "" {
		if _, err := d.lookupID(ctx, tenantExtLookup, externalID); err == nil {
			return storage.Tenant{}, ErrExists
		} else if !errors.Is(err, ErrNotFound) {
			return storage.Tenant{}, err
		}
	}
	id, err := d.allocTenantID(ctx)
	if err != nil {
		return storage.Tenant{}, err
	}
	tenant := storage.Tenant{ID: id, Name: name, ExternalID: externalID, StorageLimit: storageLimit}
	batch := storage.NewBatch().WithAccount(systemAccountID)
	if externalID != "" {
		suffix := storage.BatchSuffix(0, 0, []byte(tenantExtLookup+"/"+externalID))
		if err := batch.Assert(storage.SubspaceLookup, suffix, nil); err != nil {
			return storage.Tenant{}, err
		}
		if err := d.putLookup(batch, tenantExtLookup, externalID, id); err != nil {
			return storage.Tenant{}, err
		}
	}
	if err := d.putTenant(batch, tenant); err != nil {
		return storage.Tenant{}, err
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		if errors.Is(err, storage.ErrCASConflict) {
			return storage.Tenant{}, ErrExists
		}
		return storage.Tenant{}, err
	}
	return tenant, nil
}

// TenantByExternalID returns the tenant registered under externalID.
func (d *Local) TenantByExternalID(ctx context.Context, externalID string) (storage.Tenant, error) {
	id, err := d.lookupID(ctx, tenantExtLookup, strings.TrimSpace(externalID))
	if err != nil {
		return storage.Tenant{}, err
	}
	return d.GetTenant(ctx, id)
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

// SetTenantStorageLimit sets the tenant-wide mailbox storage cap (0 = unlimited).
func (d *Local) SetTenantStorageLimit(ctx context.Context, id uint32, limit uint64) error {
	tenant, err := d.GetTenant(ctx, id)
	if err != nil {
		return err
	}
	tenant.StorageLimit = limit
	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := d.putTenant(batch, tenant); err != nil {
		return err
	}
	return d.store.Commit(ctx, batch)
}

// TenantStorageCap returns the storage cap of accountID's tenant and the ids of all accounts
// sharing it; limit 0 means no cap. It matches mail.TenantStorageCapFunc.
// shortcut: scans every account on each call (once per delivery to a capped tenant); add a
// per-tenant account index or usage counter when instances grow past a few thousand accounts.
func (d *Local) TenantStorageCap(ctx context.Context, accountID uint32) (uint64, []uint32, error) {
	acc, err := d.getAccount(ctx, accountID)
	if errors.Is(err, ErrNotFound) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	if acc.TenantID == 0 {
		return 0, nil, nil
	}
	tenant, err := d.GetTenant(ctx, acc.TenantID)
	if errors.Is(err, ErrNotFound) {
		return 0, nil, nil
	}
	if err != nil || tenant.StorageLimit == 0 {
		return 0, nil, err
	}
	ids, err := d.TenantAccountIDs(ctx, tenant.ID)
	if err != nil {
		return 0, nil, err
	}
	return tenant.StorageLimit, ids, nil
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
	if tenant.ExternalID != "" {
		suffix := storage.BatchSuffix(0, 0, []byte(tenantExtLookup+"/"+tenant.ExternalID))
		if err := batch.Delete(storage.SubspaceLookup, suffix); err != nil {
			return DeleteTenantResult{}, err
		}
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

// validateTenantExternalID trims id; empty is allowed (no external key).
func validateTenantExternalID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if len(id) > 128 {
		return "", fmt.Errorf("directory: external_id too long (max 128 bytes)")
	}
	for _, r := range id {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", fmt.Errorf("directory: invalid external_id")
		}
	}
	return id, nil
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
