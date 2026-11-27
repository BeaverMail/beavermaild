// Package dnsname turns domain names into the form the DNS and every comparison use.
package dnsname

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// lookup is UTS 46 mapping for lookup (RFC 5891 5.2, RFC 8616): case folding, width mapping
// (fullwidth "ｅｘａｍｐｌｅ" is "example"), Punycode. STD3 rules are off so DNS names with
// underscore labels ("_dmarc.", "sel._domainkey.") convert too.
var lookup = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.Transitional(false), idna.BidiRule())

// ToASCII returns name lowercased, with every U-label as its A-label (RFC 6531 3.2: lookups and
// comparisons use A-labels). The Go resolver answers "no such host" to a non-ASCII name without
// querying, so an unconverted U-label silently turns SPF and DMARC into "none". A name IDNA
// rejects, or one that is not valid UTF-8, comes back lowercased only: it names no registered domain.
func ToASCII(name string) string {
	name = strings.TrimSpace(name)
	ascii := true
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			ascii = false
			break
		}
	}
	// Bytes that are not UTF-8 are no U-label. IDNA would read them as U+FFFD and, depending on
	// the Unicode tables of the Go release, refuse them or invent an A-label for them.
	if ascii {
		return strings.ToLower(name)
	}
	if !utf8.ValidString(name) {
		return lowerASCII(name) // strings.ToLower would also turn the bad bytes into U+FFFD
	}
	a, err := lookup.ToASCII(name)
	if err != nil {
		return strings.ToLower(name)
	}
	return strings.ToLower(a)
}

// lowerASCII lowercases A-Z and leaves every other byte as it is.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
