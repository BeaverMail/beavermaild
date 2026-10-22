// Domain and account deletion for the local directory.
package directory

import (
	"context"
	"fmt"
	"os"

	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
)

// DeleteDomainResult reports what was removed.
type DeleteDomainResult struct {
	Domain          storage.Domain
	AccountsDeleted int
}

// DeleteAccountResult reports account removal and mail purge counts.
type DeleteAccountResult struct {
	Account         storage.Account
	Email           string
	MessagesRemoved uint32
	BlobsRemoved    uint32
}

// DeleteDomain removes a domain, all its accounts, their mail metadata, and unreferenced blobs.
func (d *Local) DeleteDomain(ctx context.Context, name string, blobs *blob.FS) (DeleteDomainResult, error) {
	dom, err := d.LookupDomain(ctx, name)
	if err != nil {
		return DeleteDomainResult{}, err
	}

	accounts, err := d.accountsForDomain(ctx, dom.ID)
	if err != nil {
		return DeleteDomainResult{}, err
	}
	for _, acc := range accounts {
		if _, err := d.deleteAccount(ctx, acc, dom.Name, blobs); err != nil {
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
	if dom.MailHostname != "" {
		_ = batch.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, []byte("mhost/"+dom.MailHostname)))
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		return DeleteDomainResult{}, err
	}
	if d.dataDir != "" {
		_ = os.RemoveAll(DomainDir(d.dataDir, dom.ID))
	}

	return DeleteDomainResult{Domain: dom, AccountsDeleted: len(accounts)}, nil
}

// DeleteAccount removes one account, its mail metadata, lookup keys, quota, and unreferenced blobs.
func (d *Local) DeleteAccount(ctx context.Context, email string, blobs *blob.FS) (DeleteAccountResult, error) {
	acc, dom, err := d.ResolveEmail(ctx, email)
	if err != nil {
		return DeleteAccountResult{}, err
	}
	return d.deleteAccount(ctx, acc, dom.Name, blobs)
}

func (d *Local) deleteAccount(ctx context.Context, acc storage.Account, domName string, blobs *blob.FS) (DeleteAccountResult, error) {
	purge, err := purgeAccountMail(ctx, d.store, blobs, acc.ID)
	if err != nil {
		return DeleteAccountResult{}, err
	}

	batch := storage.NewBatch().WithAccount(acc.ID)
	if err := batch.Delete(storage.SubspaceAccount, storage.BatchSuffix(colAccount, acc.ID, nil)); err != nil {
		return DeleteAccountResult{}, err
	}
	if err := batch.Delete(storage.SubspaceAccount, storage.BatchSuffix(colCred, acc.ID, nil)); err != nil {
		return DeleteAccountResult{}, err
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		return DeleteAccountResult{}, err
	}

	email := acc.LocalPart + "@" + domName
	lookup := storage.NewBatch().WithAccount(systemAccountID)
	if err := lookup.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, []byte("acc/"+email))); err != nil {
		return DeleteAccountResult{}, err
	}
	if err := lookup.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, daccKey(acc.DomainID, acc.ID))); err != nil {
		return DeleteAccountResult{}, err
	}
	if err := lookup.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, fmt.Appendf(nil, "meta/email/%d", acc.ID))); err != nil {
		return DeleteAccountResult{}, err
	}
	if err := lookup.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, fmt.Appendf(nil, "meta/quota/%d", acc.ID))); err != nil {
		return DeleteAccountResult{}, err
	}
	if err := d.store.Commit(ctx, lookup); err != nil {
		return DeleteAccountResult{}, err
	}

	return DeleteAccountResult{
		Account:         acc,
		Email:           email,
		MessagesRemoved: purge.messagesRemoved,
		BlobsRemoved:    purge.blobsRemoved,
	}, nil
}
