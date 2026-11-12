// Mailbox name validation for IMAP CREATE/RENAME/LIST safety.
package mail

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidMailboxName is returned when a folder name contains CTL or delimiters unsafe on the wire.
var ErrInvalidMailboxName = errors.New("mail: invalid mailbox name")

// ErrMailboxLimit is returned for a name past MaxMailboxNameBytes or MaxMailboxDepth, or a
// folder that would take an account past MaxMailboxes.
var ErrMailboxLimit = errors.New("mail: mailbox limit reached")

// Mailbox limits. Nothing used to bound them: one CREATE of a 2000-level name made every later
// LIST of the account take seconds, and a 30000-byte name cost 11 s of pattern matching per LIST.
const (
	MaxMailboxNameBytes = 1024
	MaxMailboxDepth     = 32 // hierarchy levels, "a/b/c" is 3
)

// MaxMailboxes caps the folders of one account (a variable so tests can lower it).
var MaxMailboxes = 10000

// ValidateMailboxName checks RFC 3501 mailbox name constraints (CTL, { }, CRLF injection).
func ValidateMailboxName(name string) error {
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

// checkNewMailboxName applies the rules for a name being created (CREATE, RENAME target). Only
// there: a folder made before they existed must still open, rename and delete.
func checkNewMailboxName(name string) error {
	if len(name) > MaxMailboxNameBytes || strings.Count(name, "/") >= MaxMailboxDepth {
		return ErrMailboxLimit
	}
	// RFC 3501 5.1.3: international names are modified UTF-7; servers SHOULD refuse 8-bit names and
	// SHOULD check that every "&" starts a well-formed segment ("&-", or modified base64 then "-").
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 0x80:
			return ErrInvalidMailboxName
		case c == '&':
			j := i + 1
			for j < len(name) && isModifiedBase64(name[j]) {
				j++
			}
			if j >= len(name) || name[j] != '-' {
				return ErrInvalidMailboxName
			}
			i = j
		}
	}
	return nil
}

func isModifiedBase64(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == ','
}

// MailboxKey is the form mailbox names are compared in: ASCII case-insensitive like the rest of
// the server, except inside modified UTF-7 segments ("&...-"), whose base64 MUST be compared
// exactly (RFC 3501 5.1.3): "&ZeVnLIqe-" and "&ZEVNLIQE-" are different names.
func MailboxKey(name string) string {
	b := []byte(name)
	shifted := false
	for i, c := range b {
		switch {
		case shifted:
			shifted = c != '-'
		case c == '&':
			shifted = true
		case 'a' <= c && c <= 'z':
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
