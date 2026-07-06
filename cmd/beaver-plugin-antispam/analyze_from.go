// From header heuristics (reference analysis/from.rs subset).
package main

import (
	"context"
	"strings"
	"time"
)

func analyzeFrom(ctx *classifyCtx, res *classifyResult) {
	if ctx.msg.From == "" {
		res.addTag("MISSING_FROM")
	}
	if len(ctx.msg.fromAddrs) > 1 {
		res.addTag("MULTIPLE_FROM")
	}
	env := parseEmail(ctx.req.From)
	hdr := parseEmail(ctx.msg.From)
	if env.address != "" && hdr.address != "" {
		if env.address == hdr.address {
			res.addTag("FROM_EQ_ENV_FROM")
		} else {
			res.addTag("FROM_NEQ_ENV_FROM")
			if env.sld != "" && hdr.sld != "" && env.sld != hdr.sld {
				res.addTag("FORGED_SENDER")
			}
		}
	}
	if hdr.domain != "" {
		timeout := time.Duration(ctx.cfg.RBL.TimeoutMs) * time.Millisecond
		hasA, hasMX := dnsHasAOrMX(context.Background(), hdr.domain, timeout)
		if !hasA && !hasMX {
			res.addTag("FROMHOST_NORES_A_OR_MX")
		}
	}
	if ctx.msg.From != "" && !strings.Contains(ctx.msg.From, "@") {
		res.addTag("FROM_INVALID")
	}
	if ctx.req.From != "" && !strings.Contains(ctx.req.From, "@") {
		res.addTag("ENV_FROM_INVALID")
	}
}
