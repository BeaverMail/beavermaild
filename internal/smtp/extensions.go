// SMTP EHLO extensions and MAIL/RCPT parameter parsing.
package smtp

import (
	"encoding/base64"
	"strconv"
	"strings"
)

// decodeSMTPBase64 decodes a client base64 line; raw input is accepted on decode failure.
func decodeSMTPBase64(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return line
	}
	return string(raw)
}

// parseMailArg extracts the envelope sender and optional SIZE from MAIL FROM.
func parseMailArg(arg string) (address string, declaredSize int, ok bool) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 5 || !strings.EqualFold(arg[:5], "FROM:") {
		return "", 0, false
	}
	arg = strings.TrimSpace(arg[5:])
	lt := strings.IndexByte(arg, '<')
	if lt < 0 {
		return "", 0, false
	}
	gt := strings.IndexByte(arg[lt:], '>')
	if gt < 0 {
		return "", 0, false
	}
	address = strings.ToLower(strings.TrimSpace(arg[lt+1 : lt+gt]))
	for _, field := range strings.Fields(strings.ToUpper(arg[lt+gt+1:])) {
		if strings.HasPrefix(field, "SIZE=") {
			n, err := strconv.Atoi(field[5:])
			if err != nil || n < 0 {
				return "", 0, false
			}
			declaredSize = n
		}
	}
	return address, declaredSize, true
}
