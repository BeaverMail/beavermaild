// Password hashing for local directory credentials.
package directory

import (
	"sync"

	"golang.org/x/crypto/bcrypt"
)

const passwordAlgorithm = "bcrypt"

// HashPassword returns a bcrypt hash for password.
func HashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

// dummyHash stands in for the password hash of an account that does not exist: comparing against
// it gives a failed login the same bcrypt cost either way, so response time does not reveal which
// addresses have accounts.
var dummyHash = sync.OnceValue(func() []byte {
	h, err := HashPassword("beavermail: no such account")
	if err != nil {
		panic(err)
	}
	return h
})

// verifyPassword is VerifyPassword; tests count its calls to check every failed login pays one.
var verifyPassword = VerifyPassword

// VerifyPassword reports whether password matches hash.
func VerifyPassword(hash []byte, password string) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(password))
}
