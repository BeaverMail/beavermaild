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
	for _, field := range strings.Fields(arg[lt+gt+1:]) {
		upper := strings.ToUpper(field)
		switch {
		case strings.HasPrefix(upper, "SIZE="):
			n, err := strconv.Atoi(upper[5:])
			if err != nil || n < 0 {
				return "", 0, false
			}
			declaredSize = n
		case strings.HasPrefix(upper, "RET="), strings.HasPrefix(upper, "ENVID="),
			strings.HasPrefix(upper, "BODY="):
			// DSN / transfer mode parameters accepted; generation deferred.
		default:
			if strings.Contains(upper, "=") {
				return "", 0, false
			}
		}
	}
	return address, declaredSize, true
}

// parseRcptArg extracts the recipient address and accepts DSN parameters (NOTIFY, ORCPT).
func parseRcptArg(arg string) (address string, ok bool) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 3 || !strings.EqualFold(arg[:3], "TO:") {
		return "", false
	}
	arg = strings.TrimSpace(arg[3:])
	lt := strings.IndexByte(arg, '<')
	if lt < 0 {
		return "", false
	}
	gt := strings.IndexByte(arg[lt:], '>')
	if gt < 0 {
		return "", false
	}
	address = strings.ToLower(strings.TrimSpace(arg[lt+1 : lt+gt]))
	for _, field := range strings.Fields(arg[lt+gt+1:]) {
		upper := strings.ToUpper(field)
		switch {
		case strings.HasPrefix(upper, "NOTIFY="), strings.HasPrefix(upper, "ORCPT="):
			// DSN parameters accepted; notification deferred.
		default:
			if strings.Contains(upper, "=") {
				return "", false
			}
		}
	}
	return address, true
}

// parseBDAT extracts the chunk size and optional LAST flag from a BDAT argument.
func parseBDAT(arg string) (size int, last bool, ok bool) {
	fields := strings.Fields(strings.TrimSpace(arg))
	if len(fields) == 0 || len(fields) > 2 {
		return 0, false, false
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil || n < 0 {
		return 0, false, false
	}
	if len(fields) == 2 {
		if !strings.EqualFold(fields[1], "LAST") {
			return 0, false, false
		}
		last = true
	}
	return n, last, true
}
