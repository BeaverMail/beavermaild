// IMAP ID (RFC 2971).
package imap

import "strings"

// cmdID answers the client's ID with the server's; the client's fields are only checked for
// syntax, never logged or acted on (RFC 2971 3, 7). Valid in every state.
func (s *session) cmdID(tag, arg string) error {
	if !validIDParams(arg) {
		return s.tagged(tag, "BAD ID syntax")
	}
	if err := s.untagged(`ID ("name" "BeaverMail")`); err != nil {
		return err
	}
	return s.tagged(tag, "OK ID completed")
}

// validIDParams reports whether arg is an id_params_list (RFC 2971 4): NIL, or a parenthesized
// list of field-value pairs, the field a string (quoted or literal), the value a string or NIL.
func validIDParams(arg string) bool {
	rest := strings.TrimSpace(arg)
	if strings.EqualFold(rest, "NIL") {
		return true
	}
	rest, ok := strings.CutPrefix(rest, "(")
	if !ok {
		return false
	}
	isString := func(s string) bool { return s != "" && (s[0] == '"' || s[0] == '{') }
	for {
		rest = strings.TrimLeft(rest, " ")
		if after, done := strings.CutPrefix(rest, ")"); done {
			return strings.TrimSpace(after) == ""
		}
		if !isString(rest) {
			return false
		}
		if _, rest, ok = cutAString(rest); !ok {
			return false
		}
		switch {
		case len(rest) >= 3 && strings.EqualFold(rest[:3], "NIL") && (len(rest) == 3 || rest[3] == ' ' || rest[3] == ')'):
			rest = rest[3:]
		case isString(rest):
			if _, rest, ok = cutAString(rest); !ok {
				return false
			}
		default:
			return false
		}
	}
}
