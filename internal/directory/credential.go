// Credential is a persisted password hash for an account.
package directory

// Credential stores the password hash for local authentication.
type Credential struct {
	Algorithm    string `msgpack:"alg"`
	PasswordHash []byte `msgpack:"ph"`
}
