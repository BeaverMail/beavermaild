// Fallback recipients for the RFC 5321 4.5.1 postmaster mailbox.
package directory

import (
	"context"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// PostmasterLocalPart is the reserved local part every served domain must accept (RFC 5321 4.5.1).
const PostmasterLocalPart = "postmaster"

// ResolvePostmaster returns who reads postmaster mail when no account, alias or catch-all takes it:
// the active tenant admins of tenantID, else the active instance admins. tenantID 0 (bare
// "RCPT TO:<Postmaster>") goes straight to the instance admins. ErrNotFound when there is nobody.
// shortcut: scans every account (no role index); fine while postmaster fallback mail is rare.
func (d *Local) ResolvePostmaster(ctx context.Context, tenantID uint32) ([]storage.Account, error) {
	domains, err := d.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	var tenantAdmins, admins []storage.Account
	for _, dom := range domains {
		accounts, err := d.accountsForDomain(ctx, dom.ID)
		if err != nil {
			return nil, err
		}
		for _, acc := range accounts {
			if !acc.Active {
				continue
			}
			switch NormalizeRole(acc.Role) {
			case RoleTenantAdmin:
				if tenantID != 0 && dom.TenantID == tenantID {
					tenantAdmins = append(tenantAdmins, acc)
				}
			case RoleAdmin:
				admins = append(admins, acc)
			}
		}
	}
	if len(tenantAdmins) > 0 {
		return tenantAdmins, nil
	}
	if len(admins) > 0 {
		return admins, nil
	}
	return nil, ErrNotFound
}
