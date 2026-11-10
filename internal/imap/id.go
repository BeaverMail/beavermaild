// IMAP ID (RFC 2971).
package imap

import "strings"

// cmdID answers the client's ID with the server's; the client's fields are only checked for
// shape. Valid in every state.
func (s *session) cmdID(tag, arg string) error {
	arg = strings.TrimSpace(arg)
	if !strings.EqualFold(arg, "NIL") && (!strings.HasPrefix(arg, "(") || !strings.HasSuffix(arg, ")")) {
		return s.tagged(tag, "BAD ID syntax")
	}
	if err := s.untagged(`ID ("name" "BeaverMail")`); err != nil {
		return err
	}
	return s.tagged(tag, "OK ID completed")
}
