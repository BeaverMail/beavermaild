// Package dnsname turns domain names into the form the DNS and every comparison use.
package dnsname

import (
	"strings"

	"golang.org/x/net/idna"
)

// lookup is UTS 46 mapping for lookup (RFC 5891 5.2, RFC 8616): case folding, width mapping
// (fullwidth "ｅｘａｍｐｌｅ" is "example"), Punycode. STD3 rules are off so DNS names with
// underscore labels ("_dmarc.", "sel._domainkey.") convert too.
var lookup = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.Transitional(false), idna.BidiRule())

// ToASCII returns name lowercased, with every U-label as its A-label (RFC 6531 3.2: lookups and
// comparisons use A-labels). The Go resolver answers "no such host" to a non-ASCII name without
// querying, so an unconverted U-label silently turns SPF and DMARC into "none". A name IDNA
// rejects comes back lowercased only: it names no registered domain.
func ToASCII(name string) string {
	name = strings.TrimSpace(name)
	ascii := true
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToLower(name)
	}
	a, err := lookup.ToASCII(name)
	if err != nil {
		return strings.ToLower(name)
	}
	return strings.ToLower(a)
}
