// Domain and account deletion for the local directory.
package directory

import (
	"context"
	"fmt"

	"github.com/BeaverMail/beaver/internal/storage"
)

// DeleteDomainResult reports what was removed.
type DeleteDomainResult struct {
	Domain          storage.Domain
	AccountsDeleted int
}

// DeleteDomain removes a domain, all its accounts, and their mail metadata.
func (d *Local) DeleteDomain(ctx context.Context, name string) (DeleteDomainResult, error) {
	dom, err := d.LookupDomain(ctx, name)
	if err != nil {
		return DeleteDomainResult{}, err
	}

	accounts, err := d.accountsForDomain(ctx, dom.ID)
	if err != nil {
		return DeleteDomainResult{}, err
	}
	for _, acc := range accounts {
		if err := d.deleteAccount(ctx, acc, dom.Name); err != nil {
			return DeleteDomainResult{}, err
		}
	}

	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := batch.Delete(storage.SubspaceAccount, storage.BatchSuffix(colDomain, dom.ID, nil)); err != nil {
		return DeleteDomainResult{}, err
	}
	if err := batch.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, []byte("dom/"+dom.Name))); err != nil {
		return DeleteDomainResult{}, err
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		return DeleteDomainResult{}, err
	}

	return DeleteDomainResult{Domain: dom, AccountsDeleted: len(accounts)}, nil
}

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

func (d *Local) deleteAccount(ctx context.Context, acc storage.Account, domName string) error {
	if err := d.deleteMailForAccount(ctx, acc.ID); err != nil {
		return err
	}

	batch := storage.NewBatch().WithAccount(acc.ID)
	if err := batch.Delete(storage.SubspaceAccount, storage.BatchSuffix(colAccount, acc.ID, nil)); err != nil {
		return err
	}
	if err := batch.Delete(storage.SubspaceAccount, storage.BatchSuffix(colCred, acc.ID, nil)); err != nil {
		return err
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		return err
	}

	email := acc.LocalPart + "@" + domName
	lookup := storage.NewBatch().WithAccount(systemAccountID)
	if err := lookup.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, []byte("acc/"+email))); err != nil {
		return err
	}
	if err := lookup.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, []byte(fmt.Sprintf("meta/email/%d", acc.ID)))); err != nil {
		return err
	}
	return d.store.Commit(ctx, lookup)
}

func (d *Local) deleteMailForAccount(ctx context.Context, accountID uint32) error {
	// ponytail: blob files on disk are not removed; content-addressed orphans are harmless until a future GC pass.
	from := storage.AppendKeyPrefix(nil, storage.SubspaceMail, accountID, 0, 0, 5)
	to := storage.AppendKey(nil, storage.SubspaceMail, accountID, ^uint32(0), 0xff, nil)

	batch := storage.NewBatch().WithAccount(accountID)
	err := d.store.Iterate(ctx, from, to, func(k, _ []byte) error {
		parts, err := storage.DecodeKey(k)
		if err != nil {
			return err
		}
		suffix := storage.BatchSuffix(parts.Collection, parts.DocumentID, parts.Suffix)
		return batch.Delete(parts.Subspace, suffix)
	})
	if err != nil {
		return err
	}
	if len(batch.Ops()) == 0 {
		return nil
	}
	return d.store.Commit(ctx, batch)
}
