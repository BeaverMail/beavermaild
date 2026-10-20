// Domain harvest DNSBL (reference analysis/domain.rs subset, Phase 6).
package main

import (
	"net"
	"strings"
)

func analyzeDomain(ctx *classifyCtx, res *classifyResult, eng *engine) {
	if eng == nil || !ctx.cfg.RBL.Enabled {
		return
	}
	// Envelope sender and HELO domains first (as Exim dnslists on $sender_address_domain /
	// $sender_helo_name); not for submission, where they are our own users' domains.
	if ctx.req.Listener != "submission" {
		for _, d := range []string{envelopeDomain(ctx.req.From), ctx.req.EHLODomain} {
			d = strings.Trim(strings.TrimSpace(d), "[]")
			if d == "" || !strings.Contains(d, ".") || net.ParseIP(d) != nil {
				continue
			}
			d = domainSLD(d)
			if ctx.lists != nil && ctx.lists.isTrustedDomain(d) {
				continue
			}
			if ctx.rblBudget == nil || !ctx.rblBudget.take() {
				return
			}
			if listed, tag, _ := eng.rbl.checkDomain(d, ctx.cfg.RBL.forScope("domain")); listed && tag != "" {
				res.addTag(tag)
			}
		}
	}
	if ctx.harvest == nil {
		return
	}
	for d := range ctx.harvest.domains {
		if d == "" || (ctx.lists != nil && ctx.lists.isTrustedDomain(d)) {
			continue
		}
		if ctx.rblBudget == nil || !ctx.rblBudget.take() {
			break
		}
		if listed, tag, _ := eng.rbl.checkDomain(d, ctx.cfg.RBL.forScope("domain")); listed && tag != "" {
			res.addTag(tag)
		}
	}
}

// envelopeDomain returns the domain of a MAIL FROM address ("" for the null sender).
func envelopeDomain(addr string) string {
	addr = strings.Trim(strings.TrimSpace(addr), "<>")
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return addr[i+1:]
	}
	return ""
}
