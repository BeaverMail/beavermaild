package mtasts

import (
	"context"
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

func TestParseTXTRecord(t *testing.T) {
	t.Parallel()
	id, ok := parseTXTRecord([]string{`v=STSv1;`, ` id=abc123;`})
	if !ok || id != "abc123" {
		t.Fatalf("id %q ok %v", id, ok)
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
