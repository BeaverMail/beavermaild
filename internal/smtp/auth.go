// SMTP AUTH PLAIN parsing (RFC 4616).
package smtp

import (
	"encoding/base64"
	"strings"
)

// decodeAuthPlain decodes a PLAIN SASL initial response (base64 or raw).
func decodeAuthPlain(line string) (user, pass string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		raw = []byte(line)
	}
	parts := strings.Split(string(raw), "\x00")
	switch len(parts) {
	case 3:
		user = strings.TrimSpace(parts[1])
		pass = parts[2]
	case 2:
		user = strings.TrimSpace(parts[0])
		pass = parts[1]
	default:
		return "", "", false
	}
	if user == "" {
		return "", "", false
	}
	return user, pass, true
}
