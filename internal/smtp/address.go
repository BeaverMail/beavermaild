// SMTP address validation for ASCII and SMTPUTF8 paths.
package smtp

import (
	"strings"
	"unicode/utf8"
)

// addressNeedsUTF8 reports whether addr contains non-ASCII Unicode.
func addressNeedsUTF8(addr string) bool {
	for _, r := range addr {
		if r > 127 {
			return true
		}
	}
	return false
}

// validEnvelopeAddress checks minimal envelope syntax for ASCII or UTF-8 addresses.
func validEnvelopeAddress(addr string) bool {
	if !utf8.ValidString(addr) {
		return false
	}
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return false
	}
	local := addr[:at]
	domain := addr[at+1:]
	if strings.TrimSpace(local) == "" || strings.TrimSpace(domain) == "" {
		return false
	}
	if strings.ContainsAny(local, " \t\r\n") || strings.ContainsAny(domain, " \t\r\n") {
		return false
	}
	return true
}

// normalizeEnvelopeAddress lowercases ASCII addresses and preserves UTF-8 local parts.
func normalizeEnvelopeAddress(addr string) string {
	if addressNeedsUTF8(addr) {
		return addr
	}
	return strings.ToLower(addr)
}
