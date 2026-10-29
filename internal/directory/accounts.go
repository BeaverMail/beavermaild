// Account listing for the local directory.
package directory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/storage"
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

// daccMarker is set once every account has a dacc/<domain>/<account> index row.
const daccMarker = "index-dacc-v1"

// daccKey is the domain → account index row for accountID on domainID.
func daccKey(domainID, accountID uint32) []byte {
	return fmt.Appendf(nil, "dacc/%d/%d", domainID, accountID)
}

func (d *Local) putDomainAccount(batch *storage.Batch, domainID, accountID uint32) error {
	wire, err := storage.MarshalPersist(nil, 1, accountID)
	if err != nil {
		return err
	}
	return batch.Set(storage.SubspaceLookup, storage.BatchSuffix(0, 0, daccKey(domainID, accountID)), wire)
}

// ensureDomainAccountIndex backfills the domain → account index once per store (accounts created
// before the index existed), then remembers it in memory.
func (d *Local) ensureDomainAccountIndex(ctx context.Context) error {
	if d.daccReady.Load() {
		return nil
	}
	_, err := d.store.Get(ctx, counterKey(daccMarker))
	if err == nil {
		d.daccReady.Store(true)
		return nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	accounts, err := d.scanAccounts(ctx, func(storage.Account) bool { return true })
	if err != nil {
		return err
	}
	batch := storage.NewBatch().WithAccount(systemAccountID)
	for _, acc := range accounts {
		if err := d.putDomainAccount(batch, acc.DomainID, acc.ID); err != nil {
			return err
		}
	}
	marker, err := storage.MarshalPersist(nil, 1, uint32(1))
	if err != nil {
		return err
	}
	if err := batch.Set(storage.SubspaceLookup, storage.BatchSuffix(0, 0, []byte("meta/"+daccMarker)), marker); err != nil {
		return err
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		return err
	}
	d.daccReady.Store(true)
	return nil
}

// domainAccountIDs reads the account ids of domainID from the index.
func (d *Local) domainAccountIDs(ctx context.Context, domainID uint32) ([]uint32, error) {
	if err := d.ensureDomainAccountIndex(ctx); err != nil {
		return nil, err
	}
	prefix := fmt.Appendf(nil, "dacc/%d/", domainID)
	from := storage.AppendKey(nil, storage.SubspaceLookup, systemAccountID, 0, 0, prefix)
	to := storage.AppendKey(nil, storage.SubspaceLookup, systemAccountID, 0, 0, append(prefix, 0xff))
	var ids []uint32
	err := d.store.Iterate(ctx, from, to, func(_, v []byte) error {
		var id uint32
		if err := storage.UnmarshalPersist(v, &id); err != nil {
			return err
		}
		ids = append(ids, id)
		return nil
	})
	return ids, err
}

// accountsForDomain returns the accounts on domainID via the domain → account index.
func (d *Local) accountsForDomain(ctx context.Context, domainID uint32) ([]storage.Account, error) {
	ids, err := d.domainAccountIDs(ctx, domainID)
	if err != nil {
		return nil, err
	}
	out := make([]storage.Account, 0, len(ids))
	for _, id := range ids {
		acc, err := d.getAccount(ctx, id)
		if errors.Is(err, ErrNotFound) {
			continue // delete in progress: the account row goes before its index rows
		}
		if err != nil {
			return nil, err
		}
		out = append(out, acc)
	}
	return out, nil
}

// TenantAccountIDs returns the ids of every account on the domains of tenantID.
func (d *Local) TenantAccountIDs(ctx context.Context, tenantID uint32) ([]uint32, error) {
	domains, err := d.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	var ids []uint32
	for _, dom := range domains {
		if dom.TenantID != tenantID {
			continue
		}
		domIDs, err := d.domainAccountIDs(ctx, dom.ID)
		if err != nil {
			return nil, err
		}
		ids = append(ids, domIDs...)
	}
	return ids, nil
}

// scanAccounts loads every account and keeps those matching keep (index backfill only: O(all accounts)).
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
