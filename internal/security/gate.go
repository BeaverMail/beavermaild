// AuthGate tracks failed logins and enforces temporary auth rate limits.
package security

// AuthGate records authentication outcomes and reports whether auth may proceed.
// Implementations must be safe for concurrent use.
type AuthGate interface {
	AllowAuth(ip, user string) bool
	RecordAuthFailure(ip, user string)
	RecordAuthSuccess(ip, user string)
}

// NopGate disables auth rate limiting (tests and explicit opt-out).
type NopGate struct{}

func (NopGate) AllowAuth(string, string) bool        { return true }
func (NopGate) RecordAuthFailure(string, string)      {}
func (NopGate) RecordAuthSuccess(string, string)      {}
