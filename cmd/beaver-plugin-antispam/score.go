// Score finalize and spam result headers (reference score.rs finalize).
package main

import (
	"fmt"
	"sort"
	"strings"
)

type tagScore struct {
	tag   string
	score float64
}

// finalizeClassify applies tag_actions, thresholds, and builds response headers.
func finalizeClassify(id string, tags []string, cfg pluginConfig) filterResp {
	tags = uniqueTags(tags)

	for _, tag := range tags {
		if act := cfg.TagActions[tag]; act == "reject" || act == "discard" {
			return filterResp{
				ID:     id,
				Action: act,
				Tags:   tags,
				Score:  scoreFor(tags, cfg.Scores),
			}
		}
	}

	score := scoreFor(tags, cfg.Scores)
	action := "accept"
	if cfg.Thresholds.Discard > 0 && score >= cfg.Thresholds.Discard {
		action = "discard"
	} else if cfg.Thresholds.Reject > 0 && score >= cfg.Thresholds.Reject {
		action = "reject"
	}

	resp := filterResp{ID: id, Action: action, Score: score, Tags: tags}
	if action == "accept" {
		resp.Headers = buildSpamHeaders(tags, score, cfg)
	}
	return resp
}

// buildSpamHeaders returns SpamAssassin-style headers for accepted messages, which mail
// clients (e.g. Thunderbird "trust SpamAssassin headers") and Sieve rules recognize:
// X-Spam-Flag (spam only), X-Spam-Score (number), X-Spam-Level (one * per point),
// X-Spam-Status, plus X-Spam-Result with the per-rule weights.
func buildSpamHeaders(tags []string, total float64, cfg pluginConfig) map[string]string {
	isSpam := cfg.Thresholds.Spam > 0 && total >= cfg.Thresholds.Spam
	var parts []tagScore
	seen := make(map[string]struct{})
	for _, tag := range tags {
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		w := cfg.Scores[tag]
		if w == 0 && !strings.HasPrefix(tag, "X_HDR_") {
			continue
		}
		parts = append(parts, tagScore{tag: tag, score: w})
	}
	sort.Slice(parts, func(i, j int) bool {
		if parts[i].score != parts[j].score {
			return parts[i].score > parts[j].score
		}
		return parts[i].tag < parts[j].tag
	})
	var result strings.Builder
	names := make([]string, len(parts))
	for i, p := range parts {
		if i > 0 {
			result.WriteString(", ")
		}
		fmt.Fprintf(&result, "%s (%.2f)", p.tag, p.score)
		names[i] = p.tag
	}
	verdict := "No"
	if isSpam {
		verdict = "Yes"
	}
	status := fmt.Sprintf("%s, score=%.1f", verdict, total)
	if cfg.Thresholds.Spam > 0 {
		status += fmt.Sprintf(" required=%.1f", cfg.Thresholds.Spam)
	}
	tests := strings.Join(names, ",")
	if tests == "" {
		tests = "none"
	}
	headers := map[string]string{
		"X-Spam-Score":  fmt.Sprintf("%.1f", total),
		"X-Spam-Status": status + " tests=" + tests,
	}
	if level := min(int(total), 50); level > 0 {
		headers["X-Spam-Level"] = strings.Repeat("*", level)
	}
	if isSpam {
		headers["X-Spam-Flag"] = "YES"
	}
	if result.Len() > 0 {
		headers["X-Spam-Result"] = result.String()
	}
	return headers
}

func scoreFor(tags []string, weights map[string]float64) float64 {
	var sum float64
	seen := make(map[string]struct{})
	for _, tag := range tags {
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		sum += weights[tag]
	}
	return sum
}

func uniqueTags(tags []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, t := range tags {
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}
