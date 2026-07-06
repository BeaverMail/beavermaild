// Date header heuristics (reference analysis/date.rs subset).
package main

import "time"

func analyzeDate(ctx *classifyCtx, res *classifyResult) {
	if ctx.msg.Date == "" && ctx.req.BodyPath != "" {
		res.addTag("MISSING_DATE")
		return
	}
	if !ctx.msg.hasDate {
		if ctx.msg.Date != "" {
			res.addTag("INVALID_DATE")
		}
		return
	}
	now := time.Now()
	if ctx.msg.DateTime.Before(now.Add(-48 * time.Hour)) {
		res.addTag("DATE_IN_PAST")
	}
	if ctx.msg.DateTime.After(now.Add(24 * time.Hour)) {
		res.addTag("DATE_IN_FUTURE")
	}
}
