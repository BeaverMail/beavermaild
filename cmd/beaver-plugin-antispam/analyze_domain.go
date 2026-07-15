// Domain harvest DNSBL (reference analysis/domain.rs subset, Phase 6).
package main

func analyzeDomain(ctx *classifyCtx, res *classifyResult, eng *engine) {
	if ctx.harvest == nil || eng == nil || !ctx.cfg.RBL.Enabled {
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
