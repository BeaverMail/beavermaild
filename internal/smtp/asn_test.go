package smtp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestASNQueryNameIPv4(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	got, ok := asnQueryName(ip, defaultASNZoneV4, defaultASNZoneV6)
	if !ok || got != "4.3.2.1.origin.asn.cymru.com." {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestParseASNCountryTXT(t *testing.T) {
	asn, cc := parseASNCountryTXT("15169 | 8.8.8.0/24 | US | arin |")
	if asn != 15169 || cc != "US" {
		t.Fatalf("asn=%d cc=%q", asn, cc)
	}
}

func TestASNLookupDisabled(t *testing.T) {
	a := NewASNLookup(ASNLookupConfig{Enabled: false})
	asn, cc := a.Lookup(context.Background(), "8.8.8.8")
	if asn != 0 || cc != "" {
		t.Fatalf("disabled want empty, got %d %q", asn, cc)
	}
}

func TestASNLookupInjectedTXT(t *testing.T) {
	a := NewASNLookup(ASNLookupConfig{
		Enabled: true,
		LookupTXT: func(_ context.Context, name string) ([]string, error) {
			if name != "4.3.2.1.origin.asn.cymru.com." {
				t.Fatalf("query=%q", name)
			}
			return []string{"64496 | 1.2.3.0/24 | NL | ripencc |"}, nil
		},
	})
	asn, cc := a.Lookup(context.Background(), "1.2.3.4")
	if asn != 64496 || cc != "NL" {
		t.Fatalf("asn=%d cc=%q", asn, cc)
	}
}

func TestASNLookupFailOpen(t *testing.T) {
	a := NewASNLookup(ASNLookupConfig{
		Enabled: true,
		LookupTXT: func(context.Context, string) ([]string, error) {
			return nil, errors.New("dns down")
		},
	})
	asn, cc := a.Lookup(context.Background(), "1.2.3.4")
	if asn != 0 || cc != "" {
		t.Fatalf("fail-open want empty, got %d %q", asn, cc)
	}
}

func TestASNLookupSkipsLoopback(t *testing.T) {
	lookups := 0
	a := NewASNLookup(ASNLookupConfig{
		Enabled: true,
		LookupTXT: func(context.Context, string) ([]string, error) {
			lookups++
			return nil, nil
		},
	})
	a.Lookup(context.Background(), "127.0.0.1")
	if lookups != 0 {
		t.Fatal("loopback must skip DNS")
	}
}

func TestASNLookupCachesHits(t *testing.T) {
	lookups := 0
	a := NewASNLookup(ASNLookupConfig{
		Enabled:  true,
		CacheTTL: time.Hour,
		LookupTXT: func(context.Context, string) ([]string, error) {
			lookups++
			return []string{"64496 | 1.2.3.0/24 | NL | ripencc |"}, nil
		},
	})
	for i := 0; i < 3; i++ {
		asn, cc := a.Lookup(context.Background(), "1.2.3.4")
		if asn != 64496 || cc != "NL" {
			t.Fatalf("asn=%d cc=%q", asn, cc)
		}
	}
	if lookups != 1 {
		t.Fatalf("lookups=%d want 1 (cached)", lookups)
	}
}

func TestASNLookupCachesMisses(t *testing.T) {
	lookups := 0
	a := NewASNLookup(ASNLookupConfig{
		Enabled:      true,
		CacheMissTTL: time.Hour,
		LookupTXT: func(context.Context, string) ([]string, error) {
			lookups++
			return nil, errors.New("nxdomain")
		},
	})
	a.Lookup(context.Background(), "1.2.3.4")
	a.Lookup(context.Background(), "1.2.3.4")
	if lookups != 1 {
		t.Fatalf("lookups=%d want 1 for cached miss", lookups)
	}
}
