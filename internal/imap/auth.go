// IMAP AUTHENTICATE PLAIN parsing (RFC 4616).
package imap

import (
	"encoding/base64"
	"strings"
)

// decodeAuthPlain decodes a PLAIN response: base64 (RFC 3501 6.2.2) of
// [authzid] NUL authcid NUL passwd (RFC 4616 2). Anything else is malformed.
func decodeAuthPlain(line string) (authzid, user, pass string, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		return "", "", "", false
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 || parts[1] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
