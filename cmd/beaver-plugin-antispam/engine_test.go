package main

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScoreFinalizeReject(t *testing.T) {
	cfg := defaultConfig()
	tags := []string{"SPAM_TRAP", "MISSING_ESSENTIAL_HEADERS"}
	score := scoreFor(tags, cfg.Scores)
	if score < cfg.Thresholds.Reject {
		t.Fatalf("score %.2f want >= %.2f", score, cfg.Thresholds.Reject)
	}
}

func TestAuthTagsSPFFail(t *testing.T) {
	tags := authTags(&wireAuth{SPFMailFrom: "fail"})
	if len(tags) != 1 || tags[0] != "SPF_FAIL" {
		t.Fatalf("tags=%v", tags)
	}
}

func TestDMARCPolicyRejectTag(t *testing.T) {
	tags := dmarcTag("fail", "reject")
	if len(tags) != 1 || tags[0] != "DMARC_POLICY_REJECT" {
		t.Fatalf("tags=%v", tags)
	}
}

func TestExtractSubjectFoldedAndEncoded(t *testing.T) {
	raw := "Subject: =?UTF-8?Q?=5BSPAM=5D?= important\r\n" +
		" offer\r\n" +
		"\r\nbody"
	subject := extractSubject([]byte(raw))
	if !strings.Contains(strings.ToLower(subject), "[spam]") {
		t.Fatalf("subject=%q want decoded [SPAM]", subject)
	}
}

func TestGtubeSubjectTag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gtube.eml")
	body := "Subject: " + gtubeSubject + "\r\n\r\nbody"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	ctx, err := newClassifyCtx(filterReq{ID: "1", BodyPath: path}, cfg, nil, newContentRules(), newLookupLists(), nil)
	if err != nil {
		t.Fatal(err)
	}
	res := runClassify(ctx, nil)
	if !containsTag(res.tags, "GTUBE_TEST") {
		t.Fatalf("tags=%v want GTUBE_TEST", res.tags)
	}
	out := finalizeClassify("1", res.tags, cfg)
	if out.Action != "reject" {
		t.Fatalf("action=%q score=%.2f want reject", out.Action, out.Score)
	}
}

func TestBuildSpamHeadersResult(t *testing.T) {
	cfg := defaultConfig()
	h := buildSpamHeaders([]string{"SPF_FAIL", "DKIM_REJECT"}, 8, cfg)
	if h["X-Spam-Result"] == "" {
		t.Fatal("missing X-Spam-Result")
	}
	if h["X-Spam-Flag"] != "YES" || h["X-Spam-Score"] != "8.0" || h["X-Spam-Level"] != "********" {
		t.Fatalf("spam headers %v", h)
	}
	if !strings.HasPrefix(h["X-Spam-Status"], "Yes, score=8.0 required=5.0 tests=") {
		t.Fatalf("X-Spam-Status=%q", h["X-Spam-Status"])
	}

	ham := buildSpamHeaders(nil, -0.5, cfg)
	if _, ok := ham["X-Spam-Flag"]; ok {
		t.Fatalf("ham must not carry X-Spam-Flag: %v", ham)
	}
	if _, ok := ham["X-Spam-Level"]; ok {
		t.Fatalf("no level for a score below 1: %v", ham)
	}
	if ham["X-Spam-Score"] != "-0.5" || ham["X-Spam-Status"] != "No, score=-0.5 required=5.0 tests=none" {
		t.Fatalf("ham headers %v", ham)
	}
}

func TestSubjectAllCaps(t *testing.T) {
	if !subjectAllCaps("WIN BIG CASH NOW TODAY") {
		t.Fatal("expected all caps match")
	}
	if subjectAllCaps("Win big cash") {
		t.Fatal("expected mixed case to not match")
	}
}

func TestAnalyzeDateFuture(t *testing.T) {
	future := time.Now().Add(48 * time.Hour).Format(time.RFC1123Z)
	msg := &parsedMessage{Date: future, DateTime: time.Now().Add(48 * time.Hour), hasDate: true}
	var res classifyResult
	analyzeDate(&classifyCtx{msg: msg}, &res)
	if !containsTag(res.tags, "DATE_IN_FUTURE") {
		t.Fatalf("tags=%v", res.tags)
	}
}

func TestHeloBareIP(t *testing.T) {
	var res classifyResult
	analyzeEHLO(&classifyCtx{
		req: filterReq{EHLODomain: "203.0.113.1", ClientIP: "198.51.100.1"},
	}, &res)
	if !containsTag(res.tags, "HELO_BAREIP") || !containsTag(res.tags, "HELO_IP_A") {
		t.Fatalf("tags=%v", res.tags)
	}
}

func TestRDNSNone(t *testing.T) {
	var res classifyResult
	analyzeIPRev(&classifyCtx{req: filterReq{IPRevResult: "none"}}, &res)
	if !containsTag(res.tags, "RDNS_NONE") {
		t.Fatal("expected RDNS_NONE")
	}
}

func TestReceivedCount(t *testing.T) {
	var res classifyResult
	analyzeReceived(&classifyCtx{
		req: filterReq{},
		msg: &parsedMessage{received: []string{"from mx1", "from mx2"}},
	}, &res)
	if !containsTag(res.tags, "RCVD_COUNT_TWO") {
		t.Fatalf("tags=%v", res.tags)
	}
}

func TestForgedRcvdTrailTag(t *testing.T) {
	var res classifyResult
	analyzeReceived(&classifyCtx{
		msg: &parsedMessage{received: []string{
			"from forged.example (legit-ptr.example [192.0.2.1]) by mx.local with ESMTPS",
		}},
	}, &res)
	if !containsTag(res.tags, "FORGED_RCVD_TRAIL") {
		t.Fatalf("tags=%v want FORGED_RCVD_TRAIL", res.tags)
	}
}

func TestReverseIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	rev := reverseIP(ip)
	if rev == "" || !strings.Contains(rev, ".") {
		t.Fatalf("rev=%q", rev)
	}
}

func TestRBLScopeZonesFallback(t *testing.T) {
	cfg := rblConfig{
		Zones:         []string{"legacy.test"},
		ClientIPZones: []string{"ip.test"},
		URLZones:      []string{"url.test"},
	}
	if got := cfg.forScope("client_ip").Zones; len(got) != 1 || got[0] != "ip.test" {
		t.Fatalf("client zones: %v", got)
	}
	if got := cfg.forScope("domain").Zones; len(got) != 1 || got[0] != "legacy.test" {
		t.Fatalf("domain fallback zones: %v", got)
	}
	if got := cfg.forScope("url").Zones; len(got) != 1 || got[0] != "url.test" {
		t.Fatalf("url zones: %v", got)
	}
}

func TestRBLCheckerUsesInjectedLookup(t *testing.T) {
	checker := newRBLChecker()
	checker.lookupIP = func(_ context.Context, network, host string) ([]net.IP, error) {
		if network != "ip4" || host != "4.3.2.1.list.test" {
			t.Fatalf("lookup network=%q host=%q", network, host)
		}
		return []net.IP{net.IPv4(127, 0, 0, 2)}, nil
	}
	cfg := rblConfig{Enabled: true, Zones: []string{"list.test"}}
	listed, tag, failed := checker.checkIP(net.IPv4(1, 2, 3, 4), cfg)
	if !listed || failed || tag != "RBL_LIST" {
		t.Fatalf("listed=%v tag=%q failed=%v", listed, tag, failed)
	}
}

func TestRBLBudgetSharedAcrossAnalyzers(t *testing.T) {
	budget := newRBLBudget(2)
	if !budget.take() {
		t.Fatal("first take should succeed")
	}
	if !budget.take() {
		t.Fatal("second take should succeed")
	}
	if budget.take() {
		t.Fatalf("third take should fail, remaining=%d", budget.remaining)
	}
}

func TestRemoteURLRejectsPrivateTargets(t *testing.T) {
	u, err := url.Parse("https://127.0.0.1/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRemoteURL(u, true); err == nil {
		t.Fatal("private remote target accepted")
	}
}

func TestNormalizeThreadSubject(t *testing.T) {
	if got := normalizeThreadSubject("Re: Fwd: WIN BIG NOW"); got != "WIN BIG NOW" {
		t.Fatalf("normalized=%q", got)
	}
}

func TestExecutableMagic(t *testing.T) {
	if !executableMagic([]byte{'M', 'Z', 0, 0}) || executableMagic([]byte("plain")) {
		t.Fatal("executable magic mismatch")
	}
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
