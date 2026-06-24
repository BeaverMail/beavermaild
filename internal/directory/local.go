// Local directory stores tenants, domains, and accounts in the KV store.
package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/BeaverMail/beaver/internal/storage"
)

// Principal is an authenticated mailbox owner.
type Principal struct {
	AccountID  uint32
	DomainID   uint32
	LocalPart  string
	DomainName string
}

// Email returns the full address local@domain.
func (p Principal) Email() string {
	return p.LocalPart + "@" + p.DomainName
}

// Local is a filesystem-backed directory using the logical KV store.
type Local struct {
	store storage.Store
}

// NewLocal returns a directory over store.
func NewLocal(store storage.Store) *Local {
	return &Local{store: store}
}

// Authenticate checks email and password and returns the principal.
func (d *Local) Authenticate(ctx context.Context, email, password string) (Principal, error) {
	acc, dom, err := d.lookupAccount(ctx, email)
	if err != nil {
		return Principal{}, err
	}
	if !acc.Active {
		return Principal{}, ErrInactive
	}
	cred, err := d.getCred(ctx, acc.ID)
	if err != nil {
		return Principal{}, err
	}
	if err := VerifyPassword(cred.PasswordHash, password); err != nil {
		return Principal{}, ErrInvalidCredentials
	}
	return Principal{
		AccountID:  acc.ID,
		DomainID:   dom.ID,
		LocalPart:  acc.LocalPart,
		DomainName: dom.Name,
	}, nil
}

// ResolveEmail maps an address to account and domain records (no password check).
func (d *Local) ResolveEmail(ctx context.Context, email string) (storage.Account, storage.Domain, error) {
	return d.lookupAccount(ctx, email)
}

// CreateDomain registers a domain name and returns its record.
func (d *Local) CreateDomain(ctx context.Context, tenantID uint32, name string) (storage.Domain, error) {
	name, err := validateDomainName(name)
	if err != nil {
		return storage.Domain{}, err
	}
	if _, err := d.lookupDomainID(ctx, name); err == nil {
		return storage.Domain{}, ErrExists
	} else if !errors.Is(err, ErrNotFound) {
		return storage.Domain{}, err
	}

	id, err := d.nextID(ctx, "domain")
	if err != nil {
		return storage.Domain{}, err
	}
	dom := storage.Domain{ID: id, TenantID: tenantID, Name: name}
	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := d.putDomain(batch, dom); err != nil {
		return storage.Domain{}, err
	}
	if err := d.putLookup(batch, "dom", name, id); err != nil {
		return storage.Domain{}, err
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		return storage.Domain{}, err
	}
	return dom, nil
}

// CreateAccount registers an account with password and a default INBOX mailbox.
func (d *Local) CreateAccount(ctx context.Context, domainID uint32, localPart, password string) (storage.Account, error) {
	localPart = normalizeLocalPart(localPart)
	if localPart == "" {
		return storage.Account{}, fmt.Errorf("directory: empty local part")
	}
	dom, err := d.getDomain(ctx, domainID)
	if err != nil {
		return storage.Account{}, err
	}
	email := localPart + "@" + dom.Name
	if _, err := d.lookupAccountID(ctx, email); err == nil {
		return storage.Account{}, ErrExists
	} else if !errors.Is(err, ErrNotFound) {
		return storage.Account{}, err
	}

	hash, err := HashPassword(password)
	if err != nil {
		return storage.Account{}, err
	}

	id, err := d.nextID(ctx, "account")
	if err != nil {
		return storage.Account{}, err
	}
	acc := storage.Account{ID: id, DomainID: domainID, LocalPart: localPart, Active: true}
	cred := Credential{Algorithm: passwordAlgorithm, PasswordHash: hash}
	mailboxes := []storage.Mailbox{
		{ID: 1, Name: "INBOX", Role: "inbox", UIDNext: 1, UIDValidity: 1},
		{ID: 2, Name: "Sent", Role: "sent", UIDNext: 1, UIDValidity: 1},
		{ID: 3, Name: "Trash", Role: "trash", UIDNext: 1, UIDValidity: 1},
		{ID: 4, Name: "Drafts", Role: "drafts", UIDNext: 1, UIDValidity: 1},
	}

	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := d.putAccount(batch, acc); err != nil {
		return storage.Account{}, err
	}
	if err := d.putLookup(batch, "acc", email, id); err != nil {
		return storage.Account{}, err
	}
	if err := d.putCred(batch, id, cred); err != nil {
		return storage.Account{}, err
	}
	for _, mbox := range mailboxes {
		if err := d.putMailbox(batch, id, mbox); err != nil {
			return storage.Account{}, err
		}
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		return storage.Account{}, err
	}
	return acc, nil
}

func (d *Local) lookupAccount(ctx context.Context, email string) (storage.Account, storage.Domain, error) {
	id, err := d.lookupAccountID(ctx, email)
	if err != nil {
		return storage.Account{}, storage.Domain{}, err
	}
	acc, err := d.getAccount(ctx, id)
	if err != nil {
		return storage.Account{}, storage.Domain{}, err
	}
	dom, err := d.getDomain(ctx, acc.DomainID)
	if err != nil {
		return storage.Account{}, storage.Domain{}, err
	}
	return acc, dom, nil
}

func (d *Local) lookupAccountID(ctx context.Context, email string) (uint32, error) {
	local, domain, err := splitEmail(email)
	if err != nil {
		return 0, err
	}
	return d.lookupID(ctx, "acc", local+"@"+normalizeDomain(domain))
}

func (d *Local) lookupDomainID(ctx context.Context, name string) (uint32, error) {
	return d.lookupID(ctx, "dom", normalizeDomain(name))
}

func (d *Local) lookupID(ctx context.Context, kind, name string) (uint32, error) {
	wire, err := d.store.Get(ctx, lookupKey(kind, name))
	if errors.Is(err, storage.ErrNotFound) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	var id uint32
	if err := storage.UnmarshalPersist(wire, &id); err != nil {
		return 0, err
	}
	return id, nil
}

func (d *Local) getAccount(ctx context.Context, id uint32) (storage.Account, error) {
	var acc storage.Account
	if err := d.getRecord(ctx, accountKey(id), &acc); err != nil {
		return storage.Account{}, err
	}
	return acc, nil
}

func (d *Local) getDomain(ctx context.Context, id uint32) (storage.Domain, error) {
	var dom storage.Domain
	if err := d.getRecord(ctx, domainKey(id), &dom); err != nil {
		return storage.Domain{}, err
	}
	return dom, nil
}

func (d *Local) getCred(ctx context.Context, accountID uint32) (Credential, error) {
	var cred Credential
	if err := d.getRecord(ctx, credKey(accountID), &cred); err != nil {
		return Credential{}, err
	}
	return cred, nil
}

func (d *Local) getRecord(ctx context.Context, key []byte, v any) error {
	wire, err := d.store.Get(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return storage.UnmarshalPersist(wire, v)
}

func (d *Local) nextID(ctx context.Context, counter string) (uint32, error) {
	key := counterKey(counter)
	wire, err := d.store.Get(ctx, key)
	var next uint32 = 1
	if err == nil {
		if err := storage.UnmarshalPersist(wire, &next); err != nil {
			return 0, err
		}
		next++
	} else if !errors.Is(err, storage.ErrNotFound) {
		return 0, err
	}

	encoded, err := storage.MarshalPersist(nil, 1, next)
	if err != nil {
		return 0, err
	}
	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := batch.Set(storage.SubspaceLookup, storage.BatchSuffix(0, 0, []byte("meta/"+counter)), encoded); err != nil {
		return 0, err
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		return 0, err
	}
	return next, nil
}

func (d *Local) putDomain(batch *storage.Batch, dom storage.Domain) error {
	wire, err := storage.MarshalPersist(nil, 1, dom)
	if err != nil {
		return err
	}
	return batch.WithAccount(systemAccountID).Set(storage.SubspaceAccount, storage.BatchSuffix(colDomain, dom.ID, nil), wire)
}

func (d *Local) putAccount(batch *storage.Batch, acc storage.Account) error {
	wire, err := storage.MarshalPersist(nil, 1, acc)
	if err != nil {
		return err
	}
	return batch.WithAccount(acc.ID).Set(storage.SubspaceAccount, storage.BatchSuffix(colAccount, acc.ID, nil), wire)
}

func (d *Local) putCred(batch *storage.Batch, accountID uint32, cred Credential) error {
	wire, err := storage.MarshalPersist(nil, 1, cred)
	if err != nil {
		return err
	}
	return batch.WithAccount(accountID).Set(storage.SubspaceAccount, storage.BatchSuffix(colCred, accountID, nil), wire)
}

func (d *Local) putMailbox(batch *storage.Batch, accountID uint32, mbox storage.Mailbox) error {
	wire, err := storage.MarshalPersist(nil, 1, mbox)
	if err != nil {
		return err
	}
	suffix := storage.DocumentSuffix(storage.CollectionMailbox, mbox.ID, nil)
	return batch.WithAccount(accountID).Set(storage.SubspaceMail, suffix, wire)
}

func (d *Local) putLookup(batch *storage.Batch, kind, name string, id uint32) error {
	wire, err := storage.MarshalPersist(nil, 1, id)
	if err != nil {
		return err
	}
	suffix := []byte(kind + "/" + name)
	return batch.WithAccount(systemAccountID).Set(storage.SubspaceLookup, storage.BatchSuffix(0, 0, suffix), wire)
}

func splitEmail(email string) (local, domain string, err error) {
	email = strings.TrimSpace(strings.ToLower(email))
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "", "", fmt.Errorf("directory: invalid email")
	}
	return email[:at], email[at+1:], nil
}

func normalizeDomain(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func normalizeLocalPart(part string) string {
	return strings.ToLower(strings.TrimSpace(part))
}
