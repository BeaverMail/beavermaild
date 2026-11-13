package mtasts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubResolver serves TXT id "one" and the given body; fetches counts HTTPS fetches.
func stubResolver(now *time.Time, body *string, fetches *int) *Resolver {
	r := NewResolver().
		WithTXTLookup(func(context.Context, string) ([]string, error) { return []string{"v=STSv1; id=one"}, nil }).
		WithPolicyFetcher(func(context.Context, string) ([]byte, error) {
			*fetches++
			if *body == "" {
				return nil, errors.New("refused")
			}
			return []byte(*body), nil
		})
	r.SetClockForTest(func() time.Time { return *now })
	return r
}

// RFC 8461 3.3 SHOULD: a failed fetch is not retried for the same id within five minutes.
func TestResolverFetchBackoff(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	body, fetches := "", 0
	r := stubResolver(&now, &body, &fetches)
	ctx := context.Background()
	for range 3 {
		if p, _ := r.Policy(ctx, "example.com"); p != nil {
			t.Fatalf("policy %+v", p)
		}
	}
	if fetches != 1 {
		t.Fatalf("fetches %d within the backoff, want 1", fetches)
	}
	now = now.Add(fetchBackoff)
	body = enforceBody
	if p, _ := r.Policy(ctx, "example.com"); !p.Enforce() || fetches != 2 {
		t.Fatalf("after backoff: %+v, fetches %d", p, fetches)
	}
}

// RFC 8461 10.2 (go-mtasts issue #40): the cache survives a restart, so a forged NXDOMAIN right after
// it does not drop an enforce policy. The file is owner-only.
func TestResolverCacheSurvivesRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "mta-sts-cache.json")
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	body, fetches := enforceBody, 0
	first := stubResolver(&now, &body, &fetches)
	if err := first.LoadCache(path); err != nil {
		t.Fatal(err)
	}
	if p, _ := first.Policy(context.Background(), "example.com"); !p.Enforce() {
		t.Fatalf("first %+v", p)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache file %v %v", fi, err)
	}

	second := NewResolver().
		WithTXTLookup(func(context.Context, string) ([]string, error) { return nil, &net.DNSError{IsNotFound: true} }).
		WithPolicyFetcher(func(context.Context, string) ([]byte, error) { return nil, errors.New("blocked") })
	second.SetClockForTest(func() time.Time { return now.Add(30 * time.Minute) })
	if err := second.LoadCache(path); err != nil {
		t.Fatal(err)
	}
	if p, _ := second.Policy(context.Background(), "example.com"); !p.Enforce() || !p.AllowsMX("mx.example.com") || p.AllowsMX("evil.example") {
		t.Fatalf("after restart %+v; want the cached enforce policy", p)
	}

	third := NewResolver()
	third.SetClockForTest(func() time.Time { return now.Add(2 * time.Hour) }) // max_age 3600 passed
	if err := third.LoadCache(path); err != nil || len(third.byDomain) != 0 {
		t.Fatalf("expired entry loaded: %v %v", third.byDomain, err)
	}
}

// RFC 8461 3.3, 10.2: refresh fetches every cached policy even when the TXT id is unchanged and
// restarts its max_age; a failed refresh is logged unless the policy mode is none; expired entries go.
func TestResolverRefresh(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	body, fetches := enforceBody, 0
	r := stubResolver(&now, &body, &fetches)
	var logs bytes.Buffer
	r.WithLogger(slog.New(slog.NewTextHandler(&logs, nil)))
	ctx := context.Background()
	if _, err := r.Policy(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	r.byDomain["old.example"] = &cacheEntry{policy: &Policy{Domain: "old.example", Mode: ModeEnforce, MaxAge: time.Minute}, fetched: now.Add(-time.Hour)}

	now = now.Add(50 * time.Minute)
	r.refresh(ctx) // example.com fetched again, old.example dropped
	if fetches != 2 || r.byDomain["example.com"].fetched != now || r.byDomain["old.example"] != nil {
		t.Fatalf("fetches %d, entries %v", fetches, r.byDomain)
	}

	r.byDomain["none.example"] = &cacheEntry{policy: &Policy{Domain: "none.example", Mode: ModeNone, MaxAge: time.Hour, PolicyID: "x"}, fetched: now}
	body = ""
	now = now.Add(fetchBackoff)
	r.refresh(ctx)
	out := logs.String()
	if !strings.Contains(out, "policy refresh failed") || !strings.Contains(out, "domain=example.com") || strings.Contains(out, "none.example") {
		t.Fatalf("logs %q; want a warning for example.com only", out)
	}
	if p, _ := r.Policy(ctx, "example.com"); !p.Enforce() {
		t.Fatal("a failed refresh must keep the cached policy")
	}
}

// S1: the cache is bounded (bounce recipients choose which domains we fetch) and a policy with too
// many mx patterns is no policy.
func TestResolverCacheBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	body, fetches := enforceBody, 0
	r := stubResolver(&now, &body, &fetches)
	ctx := context.Background()
	for i := range maxCachedPolicies + 1 {
		if i == 1 {
			now = now.Add(time.Second) // d0 is the oldest
		}
		if p, _ := r.Policy(ctx, fmt.Sprintf("d%d.example", i)); !p.Enforce() {
			t.Fatalf("d%d: %+v", i, p)
		}
	}
	if len(r.byDomain) != maxCachedPolicies || r.byDomain["d0.example"] != nil || r.byDomain["d1.example"] == nil {
		t.Fatalf("%d entries, d0 %v", len(r.byDomain), r.byDomain["d0.example"])
	}

	body = "version: STSv1\nmode: enforce\nmax_age: 3600\n" + strings.Repeat("mx: mx.example.com\n", maxMXPatterns+1)
	if p, _ := r.Policy(ctx, "many.example"); p != nil {
		t.Fatalf("%d mx patterns accepted", len(p.MX))
	}
}

// S2: an entry fetched after "now" (the clock went back) would outlive its max_age: not loaded.
func TestLoadCacheDropsFutureEntries(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "cache.json")
	data := fmt.Sprintf(`{"a.example":{"policy":{"Domain":"a.example","Mode":"enforce","MX":["mx.a.example"],"MaxAge":3600000000000,"PolicyID":"x"},"fetched":%q},
"b.example":{"policy":{"Domain":"b.example","Mode":"enforce","MX":["mx.b.example"],"MaxAge":3600000000000,"PolicyID":"x"},"fetched":%q}}`,
		now.Add(time.Hour).Format(time.RFC3339), now.Add(-time.Minute).Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewResolver()
	r.SetClockForTest(func() time.Time { return now })
	if err := r.LoadCache(path); err != nil {
		t.Fatal(err)
	}
	if r.byDomain["a.example"] != nil || r.byDomain["b.example"] == nil {
		t.Fatalf("entries %v; want b.example only", r.byDomain)
	}
}
