// MTA-STS policy discovery via DNS TXT and HTTPS fetch (RFC 8461).
package mtasts

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/BeaverMail/beavermaild/internal/security"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
)

const (
	policyPath     = "/.well-known/mta-sts.txt"
	defaultMaxBody = 64 << 10
	fetchTimeout   = 15 * time.Second
)

// TXTLookup resolves _mta-sts.<domain> TXT records.
type TXTLookup func(ctx context.Context, name string) ([]string, error)

// PolicyFetcher downloads the HTTPS policy file for domain.
type PolicyFetcher func(ctx context.Context, domain string) ([]byte, error)

// Resolver caches MTA-STS policies keyed by recipient domain.
type Resolver struct {
	mu       sync.Mutex
	byDomain map[string]*cacheEntry
	failed   map[string]failMark // last failed fetch per domain (RFC 8461 3.3 backoff)
	lookup   TXTLookup
	fetch    PolicyFetcher
	now      func() time.Time
	log      *slog.Logger
	saveMu   sync.Mutex // serializes cache file writes, so an older snapshot never lands last
	path     string     // cache file; empty keeps the cache in memory only
}

// failMark records a failed policy fetch for one policy id.
type failMark struct {
	id string
	at time.Time
}

// fetchBackoff: after a failed fetch the same policy id is not fetched again for this long
// (RFC 8461 3.3 SHOULD: "five minutes or longer per version ID").
const fetchBackoff = 5 * time.Minute

// maxCachedPolicies bounds the cache (memory and file): the domains whose policies we fetch include
// those of bounce recipients, which senders choose. Past it the least recently fetched entry goes.
const maxCachedPolicies = 10000

type cacheEntry struct {
	policy  *Policy
	fetched time.Time
}

// NewResolver returns a resolver using system DNS and HTTPS.
func NewResolver() *Resolver {
	return &Resolver{
		byDomain: make(map[string]*cacheEntry),
		failed:   make(map[string]failMark),
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

// Policy returns the policy to apply for domain, or nil when there is none. A live policy found in DNS
// and fetched over HTTPS wins; failing that, a valid cached one still applies (RFC 8461 3.3), so blocking
// or forging the TXT record does not undo a cached enforce policy (10.2). Discovery failures never fail
// the delivery: without a cached policy the domain is treated as not implementing MTA-STS.
func (r *Resolver) Policy(ctx context.Context, domain string) (*Policy, error) {
	domain = normalizeHost(domain)
	if domain == "" {
		return nil, fmt.Errorf("mta-sts: empty domain")
	}
	records, err := r.lookup(ctx, "_mta-sts."+domain)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	cached := r.cached(domain)
	id, ok := "", false
	if err == nil {
		id, ok = parseTXTRecord(records)
	}
	if !ok || cached != nil && cached.PolicyID == id || r.backingOff(domain, id) {
		return cached, nil
	}
	policy, err := r.fetchParsed(ctx, domain, id)
	if err != nil {
		return cached, nil // an unusable policy file counts as no policy fetched (3.3)
	}
	return policy, nil
}

// fetchParsed downloads and parses the policy of domain, caching it on success and noting the failure
// for the backoff otherwise.
func (r *Resolver) fetchParsed(ctx context.Context, domain, id string) (*Policy, error) {
	body, err := r.fetch(ctx, domain)
	var policy *Policy
	if err == nil {
		policy, err = parsePolicy(domain, string(body), id)
	}
	r.mu.Lock()
	if err != nil {
		if len(r.failed) >= maxCachedPolicies {
			for d, f := range r.failed {
				if r.now().Sub(f.at) >= fetchBackoff {
					delete(r.failed, d)
				}
			}
		}
		if len(r.failed) < maxCachedPolicies { // still full: this failure just gets no backoff
			r.failed[domain] = failMark{id: id, at: r.now()}
		}
	} else {
		delete(r.failed, domain)
		if _, ok := r.byDomain[domain]; !ok && len(r.byDomain) >= maxCachedPolicies {
			r.evictOldest()
		}
		r.byDomain[domain] = &cacheEntry{policy: policy, fetched: r.now()}
	}
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	r.save()
	return policy, nil
}

// evictOldest drops the least recently fetched cache entry; r.mu is held.
func (r *Resolver) evictOldest() {
	oldest := ""
	for domain, ent := range r.byDomain {
		if oldest == "" || ent.fetched.Before(r.byDomain[oldest].fetched) {
			oldest = domain
		}
	}
	delete(r.byDomain, oldest)
}

// backingOff reports whether a fetch of this policy id failed less than fetchBackoff ago.
func (r *Resolver) backingOff(domain, id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.failed[domain]
	return ok && f.id == id && r.now().Sub(f.at) < fetchBackoff
}

// cached returns the unexpired cached policy for domain, or nil.
func (r *Resolver) cached(domain string) *Policy {
	r.mu.Lock()
	defer r.mu.Unlock()
	ent := r.byDomain[domain]
	if ent == nil || r.now().Sub(ent.fetched) >= ent.policy.MaxAge {
		return nil
	}
	return ent.policy
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
		Timeout: fetchTimeout,
		Transport: &http.Transport{DialContext: dialer.DialContext, Proxy: nil,
			TLSClientConfig: &tls.Config{CipherSuites: tlsload.AEADSuites}}, // RFC 9325 4.2
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
	// 3.2 SHOULD: only text/plain, against hosts that let users put other content at a chosen path.
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "text/plain" {
		return nil, fmt.Errorf("mta-sts: fetch %s: content type %q", url, resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxBody+1))
	if err == nil && len(body) > defaultMaxBody {
		err = fmt.Errorf("mta-sts: fetch %s: policy over %d bytes", url, defaultMaxBody) // never parse a truncated policy
	}
	return body, err
}
