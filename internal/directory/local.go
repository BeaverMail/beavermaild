// Local directory stores tenants, domains, and accounts in the KV store.
package directory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/BeaverMail/beaver/internal/storage"
)

// Principal is an authenticated mailbox owner.
type Principal struct {
	AccountID  uint32
	DomainID   uint32
	TenantID   uint32
	LocalPart  string
	DomainName string
	Role       string
}

// Email returns the full address local@domain.
func (p Principal) Email() string {
	return p.LocalPart + "@" + p.DomainName
}

// Local is a filesystem-backed directory using the logical KV store.
type Local struct {
	store     storage.Store
	dataDir   string      // optional; required for TLS/DKIM domain asset paths
	daccReady atomic.Bool // domain → account index backfilled (see ensureDomainAccountIndex)
}

// NewLocal returns a directory over store.
func NewLocal(store storage.Store) *Local {
	return &Local{store: store}
}

// SetDataDir sets the data root used for per-domain TLS/DKIM files.
func (d *Local) SetDataDir(dir string) {
	d.dataDir = strings.TrimSpace(dir)
}

// DataDir returns the configured data root (may be empty).
func (d *Local) DataDir() string { return d.dataDir }

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
		TenantID:   acc.TenantID,
		LocalPart:  acc.LocalPart,
		DomainName: dom.Name,
		Role:       NormalizeRole(acc.Role),
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
	if tenantID == 0 {
		return storage.Domain{}, fmt.Errorf("directory: tenant_id required")
	}
	if err := d.ensureTenant(ctx, tenantRecord(tenantID)); err != nil {
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

// CreateAccount registers an account with password, role user, and default mailboxes.
func (d *Local) CreateAccount(ctx context.Context, domainID uint32, localPart, password string) (storage.Account, error) {
	return d.CreateAccountRole(ctx, domainID, localPart, password, RoleUser)
}

// CreateAccountRole registers an account with an explicit directory role.
func (d *Local) CreateAccountRole(ctx context.Context, domainID uint32, localPart, password, role string) (storage.Account, error) {
	localPart = normalizeLocalPart(localPart)
	if localPart == "" {
		return storage.Account{}, fmt.Errorf("directory: empty local part")
	}
	if _, ok := ReportLocalParts[localPart]; ok {
		return storage.Account{}, fmt.Errorf("directory: local part %q is reserved for %s reports", localPart, ReportLocalParts[localPart])
	}
	role = NormalizeRole(role)
	if err := ValidateRole(role); err != nil {
		return storage.Account{}, err
	}
	dom, err := d.getDomain(ctx, domainID)
	if err != nil {
		return storage.Account{}, err
	}
	if dom.TenantID == 0 {
		return storage.Account{}, fmt.Errorf("directory: domain %d missing tenant_id", domainID)
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
	acc := storage.Account{
		ID:        id,
		DomainID:  domainID,
		TenantID:  dom.TenantID,
		LocalPart: localPart,
		Role:      role,
		Active:    true,
	}
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
	if err := d.putDomainAccount(batch, domainID, id); err != nil {
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
	return d.normalizeAccount(ctx, acc)
}

// normalizeAccount fills legacy empty role/tenant from domain defaults.
func (d *Local) normalizeAccount(ctx context.Context, acc storage.Account) (storage.Account, error) {
	acc.Role = NormalizeRole(acc.Role)
	if acc.TenantID == 0 && acc.DomainID != 0 {
		dom, err := d.getDomain(ctx, acc.DomainID)
		if err != nil {
			return storage.Account{}, err
		}
		acc.TenantID = dom.TenantID
	}
	return acc, nil
}

// GetTenant returns a tenant by id.
func (d *Local) GetTenant(ctx context.Context, id uint32) (storage.Tenant, error) {
	if id == 0 {
		return storage.Tenant{}, fmt.Errorf("directory: tenant_id required")
	}
	var tenant storage.Tenant
	if err := d.getRecord(ctx, tenantKey(id), &tenant); err != nil {
		return storage.Tenant{}, err
	}
	return tenant, nil
}

// ListTenants returns all tenants sorted by id.
func (d *Local) ListTenants(ctx context.Context) ([]storage.Tenant, error) {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceAccount, systemAccountID, 0, colTenant, 6)
	to := storage.AppendKey(nil, storage.SubspaceAccount, systemAccountID, ^uint32(0), colTenant, nil)
	var out []storage.Tenant
	err := d.store.Iterate(ctx, from, to, func(k, v []byte) error {
		var tenant storage.Tenant
		if err := storage.UnmarshalPersist(v, &tenant); err != nil {
			return err
		}
		out = append(out, tenant)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b storage.Tenant) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		default:
			return 0
		}
	})
	return out, nil
}

// SetAccountRole updates the directory role on an existing account.
func (d *Local) SetAccountRole(ctx context.Context, accountID uint32, role string) error {
	role = NormalizeRole(role)
	if err := ValidateRole(role); err != nil {
		return err
	}
	acc, err := d.getAccount(ctx, accountID)
	if err != nil {
		return err
	}
	acc.Role = role
	batch := storage.NewBatch().WithAccount(acc.ID)
	if err := d.putAccount(batch, acc); err != nil {
		return err
	}
	return d.store.Commit(ctx, batch)
}

// SetPassword replaces the credential hash for an account.
func (d *Local) SetPassword(ctx context.Context, accountID uint32, password string) error {
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("directory: password required")
	}
	if _, err := d.getAccount(ctx, accountID); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	cred := Credential{Algorithm: passwordAlgorithm, PasswordHash: hash}
	batch := storage.NewBatch().WithAccount(accountID)
	if err := d.putCred(batch, accountID, cred); err != nil {
		return err
	}
	return d.store.Commit(ctx, batch)
}

// SetActive updates whether the account may authenticate.
func (d *Local) SetActive(ctx context.Context, accountID uint32, active bool) error {
	acc, err := d.getAccount(ctx, accountID)
	if err != nil {
		return err
	}
	acc.Active = active
	batch := storage.NewBatch().WithAccount(acc.ID)
	if err := d.putAccount(batch, acc); err != nil {
		return err
	}
	return d.store.Commit(ctx, batch)
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
