package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScoreFinalizeReject(t *testing.T) {
	cfg := defaultConfig()
	tags := []string{"SPF_FAIL", "DMARC_POLICY_REJECT"}
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
	if !strings.Contains(h["X-Spam-Score"], "spam") {
		t.Fatalf("X-Spam-Score=%q", h["X-Spam-Score"])
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

func TestReverseIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	rev := reverseIP(ip)
	if rev == "" || !strings.Contains(rev, ".") {
		t.Fatalf("rev=%q", rev)
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
