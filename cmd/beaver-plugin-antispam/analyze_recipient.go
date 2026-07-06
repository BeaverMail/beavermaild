// Recipient heuristics (reference analysis/recipient.rs subset).
package main

import (
	"sort"
	"strings"
)

func analyzeRecipient(ctx *classifyCtx, res *classifyResult) {
	rcpts := uniqueAddrs(append(ctx.msg.To, append(ctx.msg.Cc, ctx.msg.Bcc...)...))
	if len(rcpts) == 0 && ctx.req.BodyPath != "" {
		res.addTag("MISSING_TO")
	}
	addRcptCountTag(res, len(rcpts))
	envSet := make(map[string]struct{})
	for _, e := range ctx.req.To {
		envSet[strings.ToLower(strings.Trim(e, "<>"))] = struct{}{}
	}
	matchAll, matchSome := true, false
	for _, r := range rcpts {
		if _, ok := envSet[r]; ok {
			matchSome = true
		} else {
			matchAll = false
		}
	}
	if len(envSet) > 0 && matchAll && len(rcpts) > 0 {
		res.addTag("TO_MATCH_ENVRCPT_ALL")
	} else if matchSome {
		res.addTag("TO_MATCH_ENVRCPT_SOME")
	}
	if len(rcpts) >= 2 && sort.StringsAreSorted(rcpts) {
		res.addTag("SORTED_RECIPS")
	}
}

func addRcptCountTag(res *classifyResult, n int) {
	switch {
	case n == 0:
		res.addTag("RCPT_COUNT_ZERO")
	case n == 1:
		res.addTag("RCPT_COUNT_ONE")
	case n <= 5:
		res.addTag("RCPT_COUNT_FIVE")
	case n <= 10:
		res.addTag("RCPT_COUNT_TEN")
	case n > 50:
		res.addTag("RCPT_COUNT_GT_50")
	}
}

func uniqueAddrs(addrs []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, a := range addrs {
		a = strings.ToLower(strings.Trim(strings.TrimSpace(a), "<>"))
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
