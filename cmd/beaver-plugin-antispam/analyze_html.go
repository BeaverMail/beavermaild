// HTML body heuristics (reference analysis/html.rs subset).
package main

import (
	"strings"
)

func analyzeHTML(ctx *classifyCtx, res *classifyResult) {
	if ctx.harvest == nil || !ctx.harvest.hasHTML {
		return
	}
	html := ctx.harvest.html
	if reDataURI.MatchString(html) {
		res.addTag("HAS_DATA_URI")
	}
	if reMetaRefresh.MatchString(html) {
		res.addTag("HTML_META_REFRESH_URL")
	}
	if strings.Count(html, "<") != strings.Count(html, ">") {
		res.addTag("HTML_UNBALANCED_TAG")
	}
	plainLen := len(strings.Fields(ctx.harvest.plain))
	if plainLen > 0 && plainLen < 4 {
		res.addTag("HTML_SHORT_1")
	}
	if strings.Contains(strings.ToLower(html), "http://") && strings.Contains(strings.ToLower(html), "https://") {
		res.addTag("HTTP_TO_HTTPS")
	}
	if strings.Contains(strings.ToLower(html), "http://") && reBareIP.MatchString(html) {
		res.addTag("HTTP_TO_IP")
	}
	if strings.Contains(strings.ToLower(html), "<img") && strings.Contains(strings.ToLower(html), "http") {
		res.addTag("HAS_EXTERNAL_IMG")
	}
	if len(ctx.harvest.urls) > 0 && plainLen < 3 {
		res.addTag("PHISHING")
	}
}
