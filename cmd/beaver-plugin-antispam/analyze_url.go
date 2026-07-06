// URL heuristics and body DNSBL (reference analysis/url.rs subset, Phase 5-6).
package main

import (
	"strings"
	"unicode"
)

func analyzeURL(ctx *classifyCtx, res *classifyResult, eng *engine) {
	if ctx.harvest == nil {
		return
	}
	if len(ctx.harvest.urls) == 1 && len(strings.Fields(ctx.harvest.plain)) <= 2 {
		res.addTag("URL_ONLY")
	}
	for u := range ctx.harvest.urls {
		if strings.Contains(u, "%00") || strings.ContainsRune(u, '\u200b') {
			res.addTag("ZERO_WIDTH_SPACE_URL")
		}
		if strings.Count(u, "http") > 2 {
			res.addTag("URL_REDIRECTOR_NESTED")
		}
		host := urlHost(u)
		if ctx.lists != nil && ctx.lists.isURLRedirector(host) {
			res.addTag("REDIRECTOR_URL")
		}
		if hasMixedScript(host) {
			res.addTag("HOMOGRAPH_URL")
		}
		if ctx.lists != nil && !ctx.lists.isTrustedDomain(host) && eng != nil && ctx.cfg.RBL.Enabled {
			if listed, tag, _ := eng.rbl.checkDomain(host, ctx.cfg.RBL); listed {
				res.addTag(tag)
			}
		}
	}
	for e := range ctx.harvest.emails {
		if ctx.lists != nil && strings.Contains(ctx.harvest.plain, e) {
			res.addTag("RCPT_IN_BODY")
		}
	}
}

func hasMixedScript(s string) bool {
	var scripts = make(map[string]struct{})
	for _, r := range s {
		if !unicode.IsLetter(r) {
			continue
		}
		if unicode.Is(unicode.Latin, r) {
			scripts["latin"] = struct{}{}
		} else {
			scripts["other"] = struct{}{}
		}
		if len(scripts) > 1 {
			return true
		}
	}
	return false
}
