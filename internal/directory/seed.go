// Default dev seed data for a single local account.
package directory

import (
	"context"
	"errors"

	"github.com/BeaverMail/beaver/internal/storage"
)

const (
	seedTenantName = "default"
	seedDomainName = "localhost"
	seedLocalPart  = "alice"
	seedPassword   = "beaver"
	seedTenantID   = DefaultTenantID
)

// SeedPassword is the default dev password for SeedDev.
func SeedPassword() string { return seedPassword }

// SeedDev creates default tenant, localhost domain, and alice@localhost if absent.
func SeedDev(ctx context.Context, d *Local) (storage.Account, error) {
	if err := d.ensureTenant(ctx, storage.Tenant{ID: seedTenantID, Name: seedTenantName}); err != nil {
		return storage.Account{}, err
	}

	domID, err := d.lookupDomainID(ctx, seedDomainName)
	if errors.Is(err, ErrNotFound) {
		dom, err := d.CreateDomain(ctx, seedTenantID, seedDomainName)
		if err != nil {
			return storage.Account{}, err
		}
		domID = dom.ID
	} else if err != nil {
		return storage.Account{}, err
	}

	email := seedLocalPart + "@" + seedDomainName
	if id, err := d.lookupAccountID(ctx, email); err == nil {
		acc, err := d.getAccount(ctx, id)
		if err != nil {
			return storage.Account{}, err
		}
		// Ensure the bootstrap account stays instance admin (pre-tenancy seeds were role user).
		if NormalizeRole(acc.Role) != RoleAdmin {
			if err := d.SetAccountRole(ctx, acc.ID, RoleAdmin); err != nil {
				return storage.Account{}, err
			}
			return d.getAccount(ctx, acc.ID)
		}
		return acc, nil
	} else if !errors.Is(err, ErrNotFound) {
		return storage.Account{}, err
	}

	return d.CreateAccountRole(ctx, domID, seedLocalPart, seedPassword, RoleAdmin)
}

func (d *Local) ensureTenant(ctx context.Context, tenant storage.Tenant) error {
	var existing storage.Tenant
	if err := d.getRecord(ctx, tenantKey(tenant.ID), &existing); err == nil {
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := d.putTenant(batch, tenant); err != nil {
		return err
	}
	return d.store.Commit(ctx, batch)
}

func (d *Local) putTenant(batch *storage.Batch, tenant storage.Tenant) error {
	wire, err := storage.MarshalPersist(nil, 1, tenant)
	if err != nil {
		return err
	}
	return batch.Set(storage.SubspaceAccount, storage.BatchSuffix(colTenant, tenant.ID, nil), wire)
}
