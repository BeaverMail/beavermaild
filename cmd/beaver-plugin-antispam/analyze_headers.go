// Generic header heuristics (reference analysis/headers.rs subset).
package main

import (
	"strings"
)

func analyzeHeaders(ctx *classifyCtx, res *classifyResult) {
	if ctx.msg == nil {
		return
	}
	essential := []string{"from", "date", "message-id"}
	missing := 0
	for _, name := range essential {
		if len(ctx.msg.headers[name]) == 0 {
			missing++
		}
	}
	if missing > 0 {
		res.addTag("MISSING_ESSENTIAL_HEADERS")
	}
	for name, vals := range ctx.msg.headers {
		norm := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		if len(vals) > 1 {
			res.addTag("MULTIPLE_UNIQUE_HEADERS")
		}
		for _, v := range vals {
			if strings.Contains(v, "::") {
				res.addTag("HEADER_EMPTY_DELIMITER")
			}
		}
		switch name {
		case "list-unsubscribe":
			res.addTag("HAS_LIST_UNSUB")
		case "precedence":
			if strings.EqualFold(vals[0], "bulk") || strings.EqualFold(vals[0], "list") {
				res.addTag("PRECEDENCE_BULK")
				res.addTag("MAILLIST")
			}
		case "x-priority":
			res.addTag("HAS_X_PRIO_" + strings.ToUpper(strings.TrimSpace(vals[0])))
		default:
			if strings.HasPrefix(name, "x-") && ctx.cfg.Scores["X_HDR_"+norm] != 0 {
				res.addTag("X_HDR_" + norm)
			}
		}
	}
}
