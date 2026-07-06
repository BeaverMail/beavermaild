// Spam trap and envelope checks (Phase 7).
package main

func analyzeSpamTrap(ctx *classifyCtx, res *classifyResult) {
	if ctx.lists == nil {
		return
	}
	for _, to := range ctx.req.To {
		if ctx.lists.isSpamTrap(to) {
			res.addTag("SPAM_TRAP")
			return
		}
	}
}
