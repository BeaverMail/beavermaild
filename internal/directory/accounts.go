// Account listing for the local directory.
package directory

import (
	"context"
	"slices"
	"strings"

	"github.com/BeaverMail/beaver/internal/storage"
)

// ListAccounts returns accounts on domain name sorted by local part.
func (d *Local) ListAccounts(ctx context.Context, domainName string) ([]storage.Account, storage.Domain, error) {
	dom, err := d.LookupDomain(ctx, domainName)
	if err != nil {
		return nil, storage.Domain{}, err
	}
	accounts, err := d.accountsForDomain(ctx, dom.ID)
	if err != nil {
		return nil, storage.Domain{}, err
	}
	slices.SortFunc(accounts, func(a, b storage.Account) int {
		return strings.Compare(a.LocalPart, b.LocalPart)
	})
	return accounts, dom, nil
}

// accountsForDomain scans lookup keys and returns accounts on domainID.
func (d *Local) accountsForDomain(ctx context.Context, domainID uint32) ([]storage.Account, error) {
	return d.scanAccounts(ctx, func(acc storage.Account) bool { return acc.DomainID == domainID })
}

// TenantAccountIDs returns the ids of every account in tenantID.
func (d *Local) TenantAccountIDs(ctx context.Context, tenantID uint32) ([]uint32, error) {
	accounts, err := d.scanAccounts(ctx, func(acc storage.Account) bool { return acc.TenantID == tenantID })
	if err != nil {
		return nil, err
	}
	ids := make([]uint32, len(accounts))
	for i, acc := range accounts {
		ids[i] = acc.ID
	}
	return ids, nil
}

// scanAccounts loads every account and keeps those matching keep.
func (d *Local) scanAccounts(ctx context.Context, keep func(storage.Account) bool) ([]storage.Account, error) {
	from := storage.AppendKey(nil, storage.SubspaceLookup, systemAccountID, 0, 0, []byte("acc/"))
	to := storage.AppendKey(nil, storage.SubspaceLookup, systemAccountID, 0, 0, []byte("acc/\xff"))

	var out []storage.Account
	err := d.store.Iterate(ctx, from, to, func(_, v []byte) error {
		var id uint32
		if err := storage.UnmarshalPersist(v, &id); err != nil {
			return err
		}
		acc, err := d.getAccount(ctx, id)
		if err != nil {
			return err
		}
		if keep(acc) {
			out = append(out, acc)
		}
		return nil
	})
	return out, err
}
