// Directory collection bytes stored under SubspaceAccount / SubspaceLookup.
package directory

const (
	colTenant  byte = 1
	colDomain  byte = 2
	colAccount byte = 3
	colCred    byte = 4
	colAPIKey  byte = 5
)

// systemAccountID is the key prefix account for global directory rows.
const systemAccountID uint32 = 0
