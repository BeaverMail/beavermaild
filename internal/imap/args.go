// IMAP string arguments shared by every command (RFC 3501 4.3, 9).
package imap

import (
	"strconv"
	"strings"
)

// cutAString parses one astring at the start of s: a quoted string with its \" and \\ escapes
// resolved, a literal as readCommandLiterals assembles it ("{n}\r\n" and the n bytes), or an atom
// up to the next space. rest has its leading spaces trimmed. Every command reads its strings
// through here, so all of them accept the three forms the grammar allows.
func cutAString(s string) (val, rest string, ok bool) {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return "", "", false
	}
	switch s[0] {
	case '"':
		val, rest, ok = cutQuotedString(s)
	case '{':
		val, rest, ok = cutLiteral(s)
	default:
		val, rest, _ = strings.Cut(s, " ")
		ok = true
	}
	return val, strings.TrimLeft(rest, " "), ok
}

// onlyAString parses s as exactly one astring, trailing spaces allowed.
func onlyAString(s string) (string, bool) {
	val, rest, ok := cutAString(s)
	return val, ok && strings.TrimSpace(rest) == ""
}

// quoteMailbox writes a mailbox name for LIST, LSUB and STATUS: INBOX as an atom, others as a
// quoted string with \ and " escaped, or a literal when the name holds 8-bit bytes (quoted
// strings are 7-bit, RFC 3501 4.3).
func quoteMailbox(name string) string {
	if strings.EqualFold(name, "INBOX") {
		return "INBOX"
	}
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return "{" + strconv.Itoa(len(name)) + "}\r\n" + name
		}
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(name) + `"`
}
