// Configurable expression rules (reference rules.rs simplified, Phase 8).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type exprRule struct {
	Scope    string  `json:"scope"`
	Match    string  `json:"match"`
	Header   string  `json:"header"`
	Tag      string  `json:"tag"`
	MinScore float64 `json:"min_score"`
	re       *regexp.Regexp
}

// loadRemoteRules loads a bounded HTTPS JSON rule list during atomic reload.
func loadRemoteRules(rawURL string) ([]exprRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, _, err := getRemote(ctx, rawURL, true, 5*time.Second, 3)
	if err != nil {
		return nil, err
	}
	var rules []exprRule
	if err := json.Unmarshal(body, &rules); err != nil {
		return nil, fmt.Errorf("antispam: parse remote rules: %w", err)
	}
	for _, rule := range rules {
		if rule.Tag == "" || (rule.Match != "" && !validRulePattern(rule.Match)) {
			return nil, fmt.Errorf("antispam: invalid remote rule")
		}
	}
	return rules, nil
}

func validRulePattern(pattern string) bool {
	_, err := regexp.Compile(pattern)
	return err == nil
}

func compileRules(cfg pluginConfig) []exprRule {
	var out []exprRule
	for _, r := range cfg.Rules {
		if r.Tag == "" {
			continue
		}
		er := r
		if r.Match != "" {
			if re, err := regexp.Compile(r.Match); err == nil {
				er.re = re
			}
		}
		out = append(out, er)
	}
	return out
}

func analyzeRules(ctx *classifyCtx, res *classifyResult, rules []exprRule) {
	if len(rules) == 0 {
		return
	}
	score := scoreFor(res.tags, ctx.cfg.Scores)
	for _, rule := range rules {
		switch strings.ToLower(rule.Scope) {
		case "any":
			if rule.MinScore > 0 && score >= rule.MinScore {
				res.addTag(rule.Tag)
			}
		case "body":
			if rule.re != nil && ctx.harvest != nil && rule.re.MatchString(ctx.harvest.plain+"\n"+ctx.harvest.html) {
				res.addTag(rule.Tag)
			}
		case "header":
			if rule.re == nil || ctx.msg == nil {
				continue
			}
			name := strings.ToLower(rule.Header)
			for h, vals := range ctx.msg.headers {
				if name != "" && h != name {
					continue
				}
				for _, v := range vals {
					if rule.re.MatchString(v) {
						res.addTag(rule.Tag)
					}
				}
			}
		case "url":
			if rule.re == nil || ctx.harvest == nil {
				continue
			}
			for u := range ctx.harvest.urls {
				if rule.re.MatchString(u) {
					res.addTag(rule.Tag)
				}
			}
		case "domain":
			if rule.re == nil || ctx.harvest == nil {
				continue
			}
			for d := range ctx.harvest.domains {
				if rule.re.MatchString(d) {
					res.addTag(rule.Tag)
				}
			}
		case "email":
			if rule.re == nil || ctx.harvest == nil {
				continue
			}
			for e := range ctx.harvest.emails {
				if rule.re.MatchString(e) {
					res.addTag(rule.Tag)
				}
			}
		}
	}
}
