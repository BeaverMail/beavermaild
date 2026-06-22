// KV key helpers for directory records and lookups.
package directory

import (
	"fmt"

	"github.com/BeaverMail/beaver/internal/storage"
)

func tenantKey(id uint32) []byte {
	return storage.AppendKey(nil, storage.SubspaceAccount, systemAccountID, id, colTenant, nil)
}

func domainKey(id uint32) []byte {
	return storage.AppendKey(nil, storage.SubspaceAccount, systemAccountID, id, colDomain, nil)
}

func accountKey(id uint32) []byte {
	return storage.AppendKey(nil, storage.SubspaceAccount, id, id, colAccount, nil)
}

func credKey(accountID uint32) []byte {
	return storage.AppendKey(nil, storage.SubspaceAccount, accountID, accountID, colCred, nil)
}

func lookupKey(kind string, name string) []byte {
	suffix := fmt.Appendf(nil, "%s/%s", kind, name)
	return storage.AppendKey(nil, storage.SubspaceLookup, systemAccountID, 0, 0, suffix)
}

func counterKey(name string) []byte {
	return lookupKey("meta", name)
}
