// EHLO hostname heuristics (reference analysis/ehlo.rs).
package main

import (
	"context"
	"net"
	"strings"
	"time"
)

func analyzeEHLO(ctx *classifyCtx, res *classifyResult) {
	ehlo := parseHostname(ctx.req.EHLODomain)
	if ehlo.fqdn == "" {
		return
	}
	clientIP := net.ParseIP(ctx.req.ClientIP)
	timeout := time.Duration(ctx.cfg.RBL.TimeoutMs) * time.Millisecond

	if ehlo.isIP {
		res.addTag("HELO_BAREIP")
		if clientIP != nil && !ehlo.ip.Equal(clientIP) {
			res.addTag("HELO_IP_A")
		}
		return
	}
	if isFQDN(ehlo) {
		ptr := strings.ToLower(strings.TrimSuffix(ctx.req.IPRevPTR, "."))
		if ptr != "" && ptr != ehlo.fqdn {
			res.addTag("HELO_IPREV_MISMATCH")
		}
		hasA, hasMX := dnsHasAOrMX(context.Background(), ehlo.fqdn, timeout)
		if !hasA && !hasMX {
			res.addTag("HELO_NORES_A_OR_MX")
		}
		return
	}
	if strings.Contains(ehlo.fqdn, "user") {
		res.addTag("RCVD_HELO_USER")
	}
	res.addTag("HELO_NOT_FQDN")
}
