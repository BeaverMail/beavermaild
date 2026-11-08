// First-install detection and admin bootstrap for an empty directory.
package directory

import (
	"context"
	"fmt"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// NeedsSetup reports whether the directory has no accounts and no API keys yet (greenfield).
// An API key counts: provisioner-only installs never create an account and must not leave /setup open.
func (d *Local) NeedsSetup(ctx context.Context) (bool, error) {
	keys, err := d.ListAPIKeys(ctx)
	if err != nil {
		return false, err
	}
	if len(keys) > 0 {
		return false, nil
	}
	domains, err := d.ListDomains(ctx)
	if err != nil {
		return false, err
	}
	for _, dom := range domains {
		accounts, _, err := d.ListAccounts(ctx, dom.Name)
		if err != nil {
			return false, err
		}
		if len(accounts) > 0 {
			return false, nil
		}
	}
	return true, nil
}

// BootstrapAdmin creates the default tenant, domain from email, and an admin account.
// Only allowed when NeedsSetup is true.
func (d *Local) BootstrapAdmin(ctx context.Context, email, password string) (storage.Account, error) {
	needed, err := d.NeedsSetup(ctx)
	if err != nil {
		return storage.Account{}, err
	}
	if !needed {
		return storage.Account{}, ErrSetupComplete
	}
	email = strings.TrimSpace(email)
	password = strings.TrimSpace(password)
	if password == "" {
		return storage.Account{}, fmt.Errorf("directory: password required")
	}
	local, domain, err := splitEmail(email)
	if err != nil {
		return storage.Account{}, err
	}
	if err := d.ensureTenant(ctx, tenantRecord(DefaultTenantID)); err != nil {
		return storage.Account{}, err
	}
	dom, _, err := d.EnsureDomain(ctx, DefaultTenantID, domain)
	if err != nil {
		return storage.Account{}, err
	}
	return d.CreateAccountRole(ctx, dom.ID, local, password, RoleAdmin)
}
