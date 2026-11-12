// MTA-STS policy discovery via DNS TXT and HTTPS fetch (RFC 8461).
package mtasts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/BeaverMail/beavermaild/internal/security"
)

const (
	policyPath      = "/.well-known/mta-sts.txt"
	defaultMaxBody  = 64 << 10
	fetchTimeout    = 15 * time.Second
	defaultCacheAge = 24 * time.Hour
)

// TXTLookup resolves _mta-sts.<domain> TXT records.
type TXTLookup func(ctx context.Context, name string) ([]string, error)

// PolicyFetcher downloads the HTTPS policy file for domain.
type PolicyFetcher func(ctx context.Context, domain string) ([]byte, error)

// Resolver caches MTA-STS policies keyed by recipient domain.
type Resolver struct {
	mu       sync.Mutex
	byDomain map[string]*cacheEntry
	lookup   TXTLookup
	fetch    PolicyFetcher
	now      func() time.Time
}

type cacheEntry struct {
	id      string
	policy  *Policy
	fetched time.Time
}

// NewResolver returns a resolver using system DNS and HTTPS.
func NewResolver() *Resolver {
	return &Resolver{
		byDomain: make(map[string]*cacheEntry),
		lookup:   net.DefaultResolver.LookupTXT,
		fetch:    httpsFetcher(false),
		now:      time.Now,
	}
}

// WithTXTLookup overrides DNS lookup (tests).
func (r *Resolver) WithTXTLookup(fn TXTLookup) *Resolver {
	if fn != nil {
		r.lookup = fn
	}
	return r
}

// httpsFetcher fetches https://mta-sts.<domain>/.well-known/mta-sts.txt.
func httpsFetcher(allowPrivate bool) PolicyFetcher {
	client := policyClient(allowPrivate)
	return func(ctx context.Context, domain string) ([]byte, error) {
		return fetchPolicy(ctx, client, "https://mta-sts."+domain+policyPath)
	}
}

// WithAllowPrivate lets policy hosts resolve to internal addresses (smtp.outbound_allow_private).
func (r *Resolver) WithAllowPrivate(allow bool) *Resolver {
	r.fetch = httpsFetcher(allow)
	return r
}

// WithPolicyFetcher overrides HTTPS fetch (tests).
func (r *Resolver) WithPolicyFetcher(fn PolicyFetcher) *Resolver {
	if fn != nil {
		r.fetch = fn
	}
	return r
}

// SetClockForTest overrides the clock (tests only).
func (r *Resolver) SetClockForTest(now func() time.Time) {
	if now != nil {
		r.now = now
	}
}

// Policy returns the cached or freshly fetched policy for domain, or nil when MTA-STS is not published.
func (r *Resolver) Policy(ctx context.Context, domain string) (*Policy, error) {
	domain = normalizeHost(domain)
	if domain == "" {
		return nil, fmt.Errorf("mta-sts: empty domain")
	}
	txtName := "_mta-sts." + domain
	records, err := r.lookup(ctx, txtName)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("mta-sts: txt lookup %s: %w", txtName, err)
	}
	id, ok := parseTXTRecord(records)
	if !ok {
		return nil, nil
	}

	r.mu.Lock()
	ent := r.byDomain[domain]
	if ent != nil && ent.id == id && ent.policy != nil && !r.expired(ent) {
		p := ent.policy
		r.mu.Unlock()
		return p, nil
	}
	r.mu.Unlock()

	body, err := r.fetch(ctx, domain)
	if err != nil {
		// RFC 8461: fetch failure without valid cache => do not enforce.
		r.mu.Lock()
		ent = r.byDomain[domain]
		if ent != nil && ent.policy != nil && !r.expired(ent) {
			p := ent.policy
			r.mu.Unlock()
			return p, nil
		}
		r.mu.Unlock()
		return nil, nil
	}
	policy, err := parsePolicy(domain, string(body), id)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.byDomain[domain] = &cacheEntry{id: id, policy: policy, fetched: r.now()}
	r.mu.Unlock()
	return policy, nil
}

func (r *Resolver) expired(ent *cacheEntry) bool {
	if ent == nil || ent.policy == nil {
		return true
	}
	ttl := ent.policy.MaxAge
	if ttl <= 0 {
		ttl = defaultCacheAge
	}
	return r.now().Sub(ent.fetched) >= ttl
}

// policyClient is the HTTPS client for policy files. It never follows redirects (RFC 8461 3.3: "HTTP
// 3xx redirects MUST NOT be followed") and, unless allowPrivate, never connects to an internal address:
// mta-sts.<domain> is chosen by whoever controls the recipient domain's DNS (SSRF).
func policyClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: fetchTimeout}
	if !allowPrivate {
		dialer.Control = security.RejectInternalDial
	}
	return &http.Client{
		Timeout:   fetchTimeout,
		Transport: &http.Transport{DialContext: dialer.DialContext, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // the 3xx is then rejected as a non-200 status
		},
	}
}

// fetchPolicy downloads url with client: only a 200 is a policy (RFC 8461 3.3).
func fetchPolicy(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mta-sts: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mta-sts: fetch %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, defaultMaxBody))
}
