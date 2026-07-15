// URL heuristics and body DNSBL (reference analysis/url.rs subset, Phase 5-6).
package main

import (
	"context"
	"strings"
	"time"
	"unicode"
)

func analyzeURL(ctx *classifyCtx, res *classifyResult, eng *engine) {
	if ctx.harvest == nil {
		return
	}
	if len(ctx.harvest.urls) == 1 && len(strings.Fields(ctx.harvest.plain)) <= 2 {
		res.addTag("URL_ONLY")
	}
	redirectChecks := 0
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
		if ctx.cfg.URLRedirects.Enabled && redirectChecks < 3 {
			redirectChecks++
			analyzeRedirect(ctx, res, eng, u, host)
		}
		if ctx.lists != nil && !ctx.lists.isTrustedDomain(host) && eng != nil && ctx.cfg.RBL.Enabled {
			if ctx.rblBudget == nil || !ctx.rblBudget.take() {
				continue
			}
			if listed, tag, _ := eng.rbl.checkDomain(host, ctx.cfg.RBL.forScope("url")); listed {
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

// analyzeRedirect follows a bounded public redirect chain and analyzes its final host.
func analyzeRedirect(ctx *classifyCtx, res *classifyResult, eng *engine, rawURL, originalHost string) {
	timeout := time.Duration(ctx.cfg.URLRedirects.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, finalURL, err := getRemote(reqCtx, rawURL, false, timeout, ctx.cfg.URLRedirects.MaxRedirects)
	if err != nil || finalURL == nil {
		return
	}
	finalHost := strings.ToLower(finalURL.Hostname())
	if finalHost == "" || strings.EqualFold(finalHost, originalHost) {
		return
	}
	res.addTag("URL_REDIRECTED")
	if hasMixedScript(finalHost) {
		res.addTag("HOMOGRAPH_URL")
	}
	if ctx.lists != nil && ctx.lists.isTrustedDomain(finalHost) {
		return
	}
	if eng != nil && ctx.cfg.RBL.Enabled && ctx.rblBudget != nil && ctx.rblBudget.take() {
		if listed, tag, _ := eng.rbl.checkDomain(finalHost, ctx.cfg.RBL.forScope("url")); listed {
			res.addTag(tag)
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
