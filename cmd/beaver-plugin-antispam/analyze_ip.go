// IP session analysis: RDNS, ASN, RBL at eom (reference analysis/ip.rs subset).
package main

import (
	"fmt"
	"net"
)

type rblBudget struct {
	remaining int
}

func newRBLBudget(max int) *rblBudget {
	if max <= 0 {
		return &rblBudget{remaining: 1 << 20}
	}
	return &rblBudget{remaining: max}
}

func (b *rblBudget) take() bool {
	if b.remaining <= 0 {
		return false
	}
	b.remaining--
	return true
}

func analyzeIP(ctx *classifyCtx, res *classifyResult, eng *engine) {
	analyzeIPRev(ctx, res)
	analyzeASN(ctx, res)
	if eng == nil || !ctx.cfg.RBL.Enabled {
		return
	}
	budget := newRBLBudget(ctx.cfg.RBL.MaxChecksPerMessage)
	ip := net.ParseIP(ctx.req.ClientIP)
	if ip == nil || ip.IsLoopback() {
		return
	}
	if eng.static.deniesIP(ctx.req.ClientIP) {
		res.addTag("IP_BLOCKED")
		return
	}
	if !budget.take() {
		return
	}
	listed, tag, _ := eng.rbl.checkIP(ip, ctx.cfg.RBL)
	if listed && tag != "" {
		res.addTag(tag)
	}
}

func analyzeIPRev(ctx *classifyCtx, res *classifyResult) {
	switch ctx.req.IPRevResult {
	case "temperror":
		res.addTag("RDNS_DNSFAIL")
	case "none":
		res.addTag("RDNS_NONE")
	}
}

func analyzeASN(ctx *classifyCtx, res *classifyResult) {
	if ctx.req.ASN > 0 {
		res.addTag(fmt.Sprintf("SOURCE_ASN_%d", ctx.req.ASN))
	}
}
