// Password hashing for local directory credentials.
package directory

import "golang.org/x/crypto/bcrypt"

const passwordAlgorithm = "bcrypt"

// HashPassword returns a bcrypt hash for password.
func HashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

// VerifyPassword reports whether password matches hash.
func VerifyPassword(hash []byte, password string) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(password))
}
