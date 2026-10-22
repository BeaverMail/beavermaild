// Account roles for thin multi-tenancy (API / admin UI gates).
package directory

import (
	"fmt"
	"strings"
)

// Directory account roles (not IMAP mailbox roles).
const (
	RoleUser        = "user"
	RoleAdmin       = "admin"
	RoleTenantAdmin = "tenant_admin"
	// RoleProvisioner manages tenants, domains, and accounts without instance ops; API keys only, never accounts.
	RoleProvisioner = "provisioner"
)

// NormalizeRole returns a canonical role or RoleUser when empty.
func NormalizeRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return RoleUser
	}
	return role
}

// ValidateRole accepts user, admin, or tenant_admin.
func ValidateRole(role string) error {
	switch NormalizeRole(role) {
	case RoleUser, RoleAdmin, RoleTenantAdmin:
		return nil
	default:
		return fmt.Errorf("directory: unknown role %q (want user, admin, or tenant_admin)", role)
	}
}
