// IMAP protocol hardening: tag and mailbox name validation.
package imap

import (
	"fmt"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// validIMAPTag reports whether tag is free of CTL and safe to echo in tagged responses.
func validIMAPTag(tag string) bool {
	if tag == "" || len(tag) > 256 {
		return false
	}
	for i := 0; i < len(tag); i++ {
		b := tag[i]
		if b < 32 || b == 127 {
			return false
		}
	}
	return true
}

func (s *session) rejectBadTag() error {
	_, err := fmt.Fprintf(s.conn, "* BAD invalid tag\r\n")
	return err
}

func mailboxNameFromArg(arg string) (string, error) {
	name := parseMailboxName(arg)
	if err := mail.ValidateMailboxName(name); err != nil {
		return "", err
	}
	return name, nil
}
