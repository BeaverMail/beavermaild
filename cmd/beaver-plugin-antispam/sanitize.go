// Email and domain parsing helpers (reference modules/sanitize.rs subset).
package main

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type parsedEmail struct {
	address string
	local   string
	domain  string
	sld     string
}

func parseEmail(addr string) parsedEmail {
	addr = strings.Trim(strings.TrimSpace(addr), "<>")
	if i := strings.LastIndexByte(addr, '@'); i > 0 {
		local := strings.ToLower(addr[:i])
		dom := strings.ToLower(addr[i+1:])
		sld, _ := publicsuffix.EffectiveTLDPlusOne(dom)
		if sld == "" {
			sld = dom
		}
		return parsedEmail{address: local + "@" + dom, local: local, domain: dom, sld: sld}
	}
	return parsedEmail{address: strings.ToLower(addr)}
}

func domainSLD(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		host = ascii
	}
	sld, _ := publicsuffix.EffectiveTLDPlusOne(host)
	if sld == "" {
		return host
	}
	return sld
}
