package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSOURCEASNTag(t *testing.T) {
	var res classifyResult
	analyzeASN(&classifyCtx{req: filterReq{ASN: 15169}}, &res)
	if !containsTag(res.tags, "SOURCE_ASN_15169") {
		t.Fatalf("tags=%v", res.tags)
	}
}

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

func TestARCTagMapping(t *testing.T) {
	cases := map[string]string{
		"pass": "ARC_ALLOW", "fail": "ARC_REJECT", "invalid": "ARC_INVALID",
		"temperror": "ARC_DNSFAIL", "none": "ARC_NA",
	}
	for res, want := range cases {
		tags := authTags(&wireAuth{ARC: res})
		if !containsTag(tags, want) {
			t.Fatalf("arc=%q tags=%v want %q", res, tags, want)
		}
	}
}

func TestForgedSenderTag(t *testing.T) {
	var res classifyResult
	analyzeFrom(&classifyCtx{
		req: filterReq{From: "billing@paypal.com"},
		msg: &parsedMessage{From: "billing@evil.example", fromAddrs: []string{"billing@evil.example"}},
		cfg: defaultConfig(),
	}, &res)
	if !containsTag(res.tags, "FORGED_SENDER") {
		t.Fatalf("tags=%v want FORGED_SENDER", res.tags)
	}
}

func TestMixedCharsetTag(t *testing.T) {
	var res classifyResult
	body := &messageBody{parts: []mimePart{
		{contentType: "text/plain", charset: "utf-8", isPlain: true},
		{contentType: "text/html", charset: "windows-1251", isHTML: true},
	}}
	analyzeMIME(&classifyCtx{
		req:     filterReq{BodyPath: "x"},
		body:    body,
		harvest: newHarvestSet(),
		lists:   newLookupLists(),
	}, &res)
	if !containsTag(res.tags, "MIXED_CHARSET") {
		t.Fatalf("tags=%v want MIXED_CHARSET", res.tags)
	}
}

func TestMimeBadExtensionByMagic(t *testing.T) {
	var res classifyResult
	body := &messageBody{parts: []mimePart{{
		contentType: "application/octet-stream",
		disposition: "attachment; filename=\"invoice.pdf\"",
		filename:    "invoice.pdf",
		body:        []byte{'M', 'Z', 0x90, 0x00},
	}}}
	analyzeMIME(&classifyCtx{
		req:     filterReq{BodyPath: "x"},
		body:    body,
		harvest: newHarvestSet(),
		lists:   newLookupLists(),
	}, &res)
	if !containsTag(res.tags, "MIME_BAD_EXTENSION") {
		t.Fatalf("tags=%v want MIME_BAD_EXTENSION from magic bytes", res.tags)
	}
}

func TestHomographURLTag(t *testing.T) {
	var res classifyResult
	h := newHarvestSet()
	h.urls["http://p\u0430ypal.com/login"] = struct{}{} // Cyrillic 'а' mixed with Latin
	analyzeURL(&classifyCtx{
		req:     filterReq{},
		cfg:     defaultConfig(),
		harvest: h,
		lists:   newLookupLists(),
	}, &res, nil)
	if !containsTag(res.tags, "HOMOGRAPH_URL") {
		t.Fatalf("tags=%v want HOMOGRAPH_URL", res.tags)
	}
}

func TestMultipartHarvest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mp.eml")
	raw := "MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nvisit http://plain.example/x\r\n" +
		"--b\r\nContent-Type: text/html\r\n\r\n<a href=\"http://html.example/y\">c</a>\r\n" +
		"--b--\r\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	_, h, err := loadMessageBody(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.domains) == 0 {
		t.Fatalf("expected harvested domains, got none")
	}
}
