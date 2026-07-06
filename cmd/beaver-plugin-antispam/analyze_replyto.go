// Reply-To heuristics (reference analysis/replyto.rs subset).
package main

import "strings"

func analyzeReplyTo(ctx *classifyCtx, res *classifyResult) {
	if ctx.msg.ReplyTo == "" {
		return
	}
	res.addTag("HAS_REPLYTO")
	rt := parseEmail(ctx.msg.ReplyTo)
	fr := parseEmail(ctx.msg.From)
	if rt.address != "" && fr.address != "" {
		if rt.address == fr.address {
			res.addTag("REPLYTO_EQ_FROM")
		} else if rt.sld != fr.sld {
			res.addTag("REPLYTO_DOM_NEQ_FROM_DOM")
			res.addTag("SPOOF_REPLYTO")
		}
	}
	if strings.Contains(strings.ToLower(ctx.msg.headersText("list-unsubscribe")), "http") {
		if rt.address != fr.address {
			res.addTag("SPOOF_REPLYTO")
		}
	}
}
