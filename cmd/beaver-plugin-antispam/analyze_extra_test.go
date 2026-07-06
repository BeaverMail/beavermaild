package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSpamTrapList(t *testing.T) {
	dir := t.TempDir()
	anti := filepath.Join(dir, "antispam")
	if err := os.MkdirAll(anti, 0o755); err != nil {
		t.Fatal(err)
	}
	trap := filepath.Join(anti, "spam-traps.txt")
	if err := os.WriteFile(trap, []byte("trap@example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.Lists.SpamTraps = []string{"spam-traps.txt"}
	lists := newLookupLists()
	lists.reload(cfg, dir)
	var res classifyResult
	analyzeSpamTrap(&classifyCtx{
		req:   filterReq{To: []string{"trap@example.com"}},
		lists: lists,
	}, &res)
	if !containsTag(res.tags, "SPAM_TRAP") {
		t.Fatalf("tags=%v", res.tags)
	}
}

func TestExprRuleBody(t *testing.T) {
	cfg := defaultConfig()
	cfg.Rules = []exprRule{{Scope: "body", Match: "(?i)viagra", Tag: "BODY_VIAGRA"}}
	rules := compileRules(cfg)
	var res classifyResult
	analyzeRules(&classifyCtx{
		cfg:     cfg,
		harvest: &harvestSet{plain: "buy viagra now"},
	}, &res, rules)
	if !containsTag(res.tags, "BODY_VIAGRA") {
		t.Fatal("expected BODY_VIAGRA rule tag")
	}
}

func TestHarvestURLs(t *testing.T) {
	h := newHarvestSet()
	harvestFromText(h, "see http://evil.example/phish")
	if len(h.urls) != 1 {
		t.Fatalf("urls=%d", len(h.urls))
	}
}

func TestParseEmailSLD(t *testing.T) {
	pe := parseEmail("User@Mail.Example.COM")
	if pe.sld != "example.com" {
		t.Fatalf("sld=%q", pe.sld)
	}
}
