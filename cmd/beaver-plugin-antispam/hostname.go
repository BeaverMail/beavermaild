// EHLO hostname parsing (reference modules/sanitize.rs subset).
package main

import (
	"net"
	"strings"
)

type parsedHostname struct {
	fqdn    string
	sld     string
	ip      net.IP
	isIP    bool
	hasSLD  bool
}

// parseHostname parses EHLO/HELO identity from wire ehlo_domain.
func parseHostname(ehlo string) parsedHostname {
	ehlo = strings.TrimSpace(strings.TrimSuffix(ehlo, "."))
	if ehlo == "" {
		return parsedHostname{}
	}
	if ip := net.ParseIP(ehlo); ip != nil {
		return parsedHostname{fqdn: ehlo, ip: ip, isIP: true}
	}
	lower := strings.ToLower(ehlo)
	parts := strings.Split(lower, ".")
	hasSLD := len(parts) >= 2 && parts[len(parts)-1] != "" && parts[len(parts)-2] != ""
	sld := ""
	if hasSLD {
		sld = parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return parsedHostname{fqdn: lower, sld: sld, hasSLD: hasSLD}
}

func isFQDN(h parsedHostname) bool {
	return !h.isIP && h.hasSLD && strings.Contains(h.fqdn, ".")
}
