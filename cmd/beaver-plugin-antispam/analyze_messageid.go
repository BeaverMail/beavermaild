// Message-ID heuristics (reference analysis/messageid.rs subset).
package main

import (
	"net"
	"strings"
)

func analyzeMessageID(ctx *classifyCtx, res *classifyResult) {
	mid := ctx.msg.MessageID
	if mid == "" {
		res.addTag("MISSING_MID")
		return
	}
	if !strings.HasPrefix(mid, "<") && !strings.Contains(mid, "@") {
		res.addTag("MID_MISSING_BRACKETS")
	}
	rhs := mid
	if i := strings.LastIndexByte(mid, '@'); i >= 0 {
		rhs = mid[i+1:]
	}
	rhs = strings.Trim(rhs, "<>")
	if ip := net.ParseIP(rhs); ip != nil {
		res.addTag("MID_BARE_IP")
	}
	if !strings.Contains(rhs, ".") {
		res.addTag("MID_RHS_NOT_FQDN")
	}
	if strings.HasPrefix(strings.ToLower(rhs), "www.") {
		res.addTag("MID_RHS_WWW")
	}
	if len(mid) > 255 {
		res.addTag("MID_RHS_TOO_LONG")
	}
	checkMidContains(res, mid, ctx.msg.From, "FROM")
	checkMidContains(res, mid, ctx.req.From, "ENV_FROM")
	for _, to := range append(ctx.req.To, ctx.msg.To...) {
		checkMidContains(res, mid, to, "TO")
	}
}

func checkMidContains(res *classifyResult, mid, addr, suffix string) {
	pe := parseEmail(addr)
	if pe.local != "" && strings.Contains(strings.ToLower(mid), pe.local) {
		res.addTag("MID_CONTAINS_" + suffix)
	}
}
