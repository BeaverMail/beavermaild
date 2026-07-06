// MIME structure heuristics (reference analysis/mime.rs subset).
package main

import (
	"strings"
)

func analyzeMIME(ctx *classifyCtx, res *classifyResult) {
	if ctx.body == nil {
		return
	}
	if ctx.body.mimeVersion == "" && ctx.req.BodyPath != "" {
		res.addTag("MISSING_MIME_VERSION")
	}
	if ctx.body.empty {
		res.addTag("COMPLETELY_EMPTY")
	}
	if ctx.harvest != nil && ctx.harvest.hasHTML && !ctx.harvest.hasPlain {
		res.addTag("MIME_HTML_ONLY")
	}
	for _, p := range ctx.body.parts {
		if p.filename != "" && ctx.lists != nil && ctx.lists.isBadExtension(p.filename) {
			res.addTag("MIME_BAD_EXTENSION")
		}
		if strings.Contains(strings.ToLower(p.disposition), "attachment") {
			res.addTag("HAS_ATTACHMENT")
		}
		cte := strings.ToLower(p.contentType)
		if strings.Contains(cte, "multipart") && len(ctx.body.parts) == 1 {
			res.addTag("MIME_MA_MISSING_TEXT")
		}
	}
	if ctx.harvest != nil && len(ctx.harvest.urls) == 1 && len(strings.Fields(ctx.harvest.plain)) < 5 {
		res.addTag("BODY_URI_ONLY")
	}
}
