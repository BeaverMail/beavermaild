// Mailbox name validation for IMAP CREATE/RENAME/LIST safety.
package mail

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidMailboxName is returned when a folder name contains CTL or delimiters unsafe on the wire.
var ErrInvalidMailboxName = errors.New("mail: invalid mailbox name")

// ValidateMailboxName checks RFC 3501 mailbox name constraints (CTL, { }, CRLF injection).
func ValidateMailboxName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("mail: empty mailbox name")
	}
	if strings.EqualFold(name, "INBOX") {
		return nil
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b < 32 || b == 127 || b == '{' || b == '}' {
			return ErrInvalidMailboxName
		}
	}
	return nil
}
