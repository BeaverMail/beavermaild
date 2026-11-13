package mtasts

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParsePolicyGoogle(t *testing.T) {
	t.Parallel()
	body := `version: STSv1
mode: enforce
mx: smtp.google.com
mx: aspmx.l.google.com
mx: *.aspmx.l.google.com
max_age: 86400
`
	p, err := parsePolicy("google.com", body, "id1")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enforce() || p.MaxAge != 24*time.Hour {
		t.Fatalf("policy %+v", p)
	}
	if !p.AllowsMX("aspmx.l.google.com") || !p.AllowsMX("alt1.aspmx.l.google.com") {
		t.Fatal("expected google mx match")
	}
	if p.AllowsMX("evil.example.com") {
		t.Fatal("unexpected mx match")
	}
}

func TestMXMatchWildcard(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"*.aspmx.l.google.com", "alt1.aspmx.l.google.com", true},
		{"*.aspmx.l.google.com", "aspmx.l.google.com", false},
		{"mx.example.com", "mx.example.com", true},
	}
	for _, tc := range cases {
		if got := mxMatch(tc.pattern, tc.host); got != tc.want {
			t.Fatalf("%s ~ %s got %v", tc.pattern, tc.host, got)
		}
	}
}

// RFC 8461 3.1: only records starting with "v=STSv1;" count, exactly one must remain, and it must be
// valid. (net.LookupTXT already joins the strings of one record.)
func TestParseTXTRecord(t *testing.T) {
	t.Parallel()
	cases := []struct {
		records []string
		id      string
	}{
		{[]string{"v=STSv1; id=abc123;"}, "abc123"},
		{[]string{"v=STSv1 ;id=abc123"}, "abc123"},
		{[]string{"v=spf1 -all", "v=STSv1; id=abc123; ext=x"}, "abc123"},
		{[]string{"v=STSv1; id=first; id=second"}, "first"},
		{[]string{"v=STSv1; id=one;", "v=STSv1; id=two;"}, ""}, // two policies: none
		{[]string{"v=STSv1;", " id=abc123;"}, ""},              // two records, the STSv1 one has no id
		{[]string{"id=abc123; v=STSv1"}, ""},                   // must begin with the version
		{[]string{"v=STSv1; id=abc-123"}, ""},                  // id is ALPHA / DIGIT
		{[]string{"v=STSv1; id=" + strings.Repeat("a", 33)}, ""},
		{[]string{"v=STSv1; id=abc; junk"}, ""},
		{[]string{"v=STSv1id=abc"}, ""},
	}
	for _, tc := range cases {
		id, ok := parseTXTRecord(tc.records)
		if id != tc.id || ok != (tc.id != "") {
			t.Errorf("%q: id %q ok %v, want %q", tc.records, id, ok, tc.id)
		}
	}
}

// RFC 8461 3.2.
func TestParsePolicyFields(t *testing.T) {
	t.Parallel()
	ok := func(body string) *Policy {
		t.Helper()
		p, err := parsePolicy("example.com", body, "id1")
		if err != nil {
			t.Fatalf("%q: %v", body, err)
		}
		return p
	}
	if p := ok("version: STSv1\nmode: none\nmax_age: 0\n"); p.Mode != ModeNone || p.MaxAge != 0 {
		t.Fatalf("none without mx, max_age 0: %+v", p)
	}
	if p := ok("version: STSv1\nmode: enforce\nmode: none\nmx: mx.example.com\nmax_age: 60\nmax_age: 1\n"); !p.Enforce() || p.MaxAge != time.Minute {
		t.Fatalf("repeated fields: the first counts: %+v", p)
	}
	if p := ok("version: STSv1\nmode: testing\nmx: a.example.com\nmx: b.example.com\nmax_age: 9999999999\nfuture: x\n"); p.MaxAge != maxAgeLimit*time.Second || len(p.MX) != 2 {
		t.Fatalf("max_age clamped, mx repeated, unknown ignored: %+v", p)
	}
	for _, body := range []string{
		"mode: enforce\nmx: mx.example.com\nmax_age: 60\n",                  // no version
		"version: STSv1\nmx: mx.example.com\nmax_age: 60\n",                 // no mode
		"version: STSv1\nmode: enforce\nmx: mx.example.com\n",               // no max_age
		"version: STSv1\nmode: enforce\nmax_age: 60\n",                      // no mx
		"version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: +60\n", // 1*10 DIGIT
		"version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 12345678901\n",
	} {
		if _, err := parsePolicy("example.com", body, "id1"); err == nil {
			t.Errorf("%q accepted", body)
		}
	}
}

const enforceBody = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 3600\n"

// RFC 8461 3.3 / 10.2: once an enforce policy is cached, losing the TXT record (forged NXDOMAIN, DNS
// error, junk record) or the policy file does not drop it. Before: NXDOMAIN or junk returned no policy,
// a DNS error or a broken policy file failed the delivery.
func TestResolverKeepsCachedPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	txt := func(context.Context, string) ([]string, error) { return []string{"v=STSv1; id=one"}, nil }
	body := enforceBody
	r := NewResolver().
		WithTXTLookup(func(ctx context.Context, name string) ([]string, error) { return txt(ctx, name) }).
		WithPolicyFetcher(func(context.Context, string) ([]byte, error) { return []byte(body), nil })
	r.SetClockForTest(func() time.Time { return now })
	if p, err := r.Policy(ctx, "example.com"); err != nil || !p.Enforce() {
		t.Fatalf("first %+v %v", p, err)
	}
	body = "garbage"
	for name, lookup := range map[string]TXTLookup{
		"nxdomain": func(context.Context, string) ([]string, error) { return nil, &net.DNSError{IsNotFound: true} },
		"servfail": func(context.Context, string) ([]string, error) { return nil, &net.DNSError{IsTemporary: true} },
		"junk":     func(context.Context, string) ([]string, error) { return []string{"v=STSv1"}, nil },
		"new id":   func(context.Context, string) ([]string, error) { return []string{"v=STSv1; id=two"}, nil },
	} {
		txt = lookup
		if p, err := r.Policy(ctx, "example.com"); err != nil || !p.Enforce() {
			t.Errorf("%s: %+v %v; want the cached enforce policy", name, p, err)
		}
	}
	now = now.Add(time.Hour)
	if p, err := r.Policy(ctx, "example.com"); err != nil || p != nil {
		t.Fatalf("expired cache: %+v %v; want no policy", p, err)
	}
}

// RFC 8461 3.1, 3.3: without a cached policy, a DNS error or an unusable policy file means delivering
// as though the domain had no MTA-STS, never a delivery error.
func TestResolverDiscoveryFailureIsNoPolicy(t *testing.T) {
	t.Parallel()
	for name, r := range map[string]*Resolver{
		"servfail": NewResolver().WithTXTLookup(func(context.Context, string) ([]string, error) {
			return nil, &net.DNSError{IsTemporary: true}
		}),
		"bad policy": NewResolver().
			WithTXTLookup(func(context.Context, string) ([]string, error) { return []string{"v=STSv1; id=one"}, nil }).
			WithPolicyFetcher(func(context.Context, string) ([]byte, error) { return []byte("mode: enforce"), nil }),
		"fetch fails": NewResolver().
			WithTXTLookup(func(context.Context, string) ([]string, error) { return []string{"v=STSv1; id=one"}, nil }).
			WithPolicyFetcher(func(context.Context, string) ([]byte, error) { return nil, errors.New("refused") }),
	} {
		if p, err := r.Policy(context.Background(), "example.com"); err != nil || p != nil {
			t.Errorf("%s: %+v %v; want no policy, no error", name, p, err)
		}
	}
}

func TestResolverCacheAndFetch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	fetches := 0
	r := NewResolver().
		WithTXTLookup(func(context.Context, string) ([]string, error) {
			return []string{"v=STSv1; id=policy1;"}, nil
		}).
		WithPolicyFetcher(func(context.Context, string) ([]byte, error) {
			fetches++
			return []byte(`version: STSv1
mode: enforce
mx: mx.test
max_age: 3600
`), nil
		})
	r.SetClockForTest(func() time.Time { return now })

	p1, err := r.Policy(ctx, "example.com")
	if err != nil || p1 == nil || !p1.Enforce() {
		t.Fatalf("first policy %+v err %v", p1, err)
	}
	_, err = r.Policy(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if fetches != 1 {
		t.Fatalf("fetches %d want 1", fetches)
	}

	now = now.Add(30 * time.Minute)
	_, err = r.Policy(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if fetches != 1 {
		t.Fatalf("cached fetches %d want 1", fetches)
	}
}

func TestResolverNoTXT(t *testing.T) {
	t.Parallel()
	r := NewResolver().WithTXTLookup(func(context.Context, string) ([]string, error) {
		return nil, nil
	})
	p, err := r.Policy(context.Background(), "example.com")
	if err != nil || p != nil {
		t.Fatalf("got %v err %v", p, err)
	}
}
