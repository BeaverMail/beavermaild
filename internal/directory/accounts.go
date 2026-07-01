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
		if acc.DomainID == domainID {
			out = append(out, acc)
		}
		return nil
	})
	return out, err
}
