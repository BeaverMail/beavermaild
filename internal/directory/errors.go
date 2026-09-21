// Directory errors.
package directory

import "errors"

var (
	ErrNotFound           = errors.New("directory: not found")
	ErrExists             = errors.New("directory: already exists")
	ErrInvalidCredentials = errors.New("directory: invalid credentials")
	ErrInactive           = errors.New("directory: account inactive")
	ErrSetupComplete      = errors.New("directory: setup already complete")
	ErrForbiddenDefault   = errors.New("directory: cannot delete default tenant")
)
