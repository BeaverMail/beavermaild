// MX host lookup for outbound SMTP delivery.
package smtp

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BeaverMail/beavermaild/internal/dnsname"
)

const smtpPort = "25"

// errNullMX is a domain that publishes "MX 0 ." (RFC 7505): it accepts no mail at all.
var errNullMX error = nullMXError{}

type nullMXError struct{}

func (nullMXError) Error() string { return "smtp: domain does not accept mail (null MX, RFC 7505)" }

// EnhancedStatus is the code RFC 7505 4.1 and 6 register for it: "Recipient address has null MX".
func (nullMXError) EnhancedStatus() string { return "5.1.10" }

// LookupHosts returns MX targets as host:port, lowest preference first (RFC 5321 5.1).
func LookupHosts(ctx context.Context, domain string) ([]string, error) {
	domain = dnsname.ToASCII(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return nil, fmt.Errorf("smtp: empty domain")
	}
	records, err := lookupMX(ctx, domain)
	return mxTargets(domain, records, err, func() error {
		_, err := net.DefaultResolver.LookupHost(ctx, domain)
		return err
	})
}

// mxTargets turns an MX answer into delivery targets: no MX record means the domain is its own
// implicit MX when it has an address (RFC 5321 5.1), "." is a null MX (RFC 7505), and hosts of equal
// preference are tried in random order (5.1 SHOULD).
func mxTargets(domain string, records []*net.MX, err error, lookupAddr func() error) ([]string, error) {
	var dnsErr *net.DNSError
	if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		return nil, WrapDNS(err)
	}
	if len(records) == 0 {
		if err := lookupAddr(); err != nil {
			return nil, WrapDNS(err)
		}
		return []string{net.JoinHostPort(domain, smtpPort)}, nil
	}
	rand.Shuffle(len(records), func(i, j int) { records[i], records[j] = records[j], records[i] })
	sort.SliceStable(records, func(i, j int) bool { return records[i].Pref < records[j].Pref })
	var out []string
	for _, mx := range records {
		if host := strings.TrimSuffix(mx.Host, "."); host != "" {
			out = append(out, net.JoinHostPort(host, smtpPort))
		}
	}
	if len(out) == 0 {
		return nil, &DeliveryError{Err: errNullMX, Permanent: true}
	}
	return out, nil
}

// DomainFromAddress returns the domain part of an email address.
func DomainFromAddress(addr string) (string, error) {
	addr = strings.TrimSpace(strings.ToLower(addr))
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return "", fmt.Errorf("smtp: invalid address %q", addr)
	}
	return dnsname.ToASCII(addr[at+1:]), nil // RFC 6531 3.2: lookups and comparisons use A-labels
}

// lookupMX resolves MX records (a variable so tests can answer without DNS).
var lookupMX = net.DefaultResolver.LookupMX

// senderNullMXTimeout bounds the MAIL FROM null MX check: a slow DNS answer lets the mail through.
const senderNullMXTimeout = 5 * time.Second

// nullMXCache remembers answers for a while, so a sender domain repeated across sessions costs one
// lookup. Bounded: when full, expired entries go, and if none expired the cache restarts empty.
var nullMXCache = struct {
	sync.Mutex
	m map[string]nullMXEntry
}{m: map[string]nullMXEntry{}}

type nullMXEntry struct {
	null  bool
	until time.Time
}

const (
	nullMXCacheTTL  = time.Hour
	nullMXCacheSize = 10000
)

// isNullMX reports whether domain publishes only a null MX (RFC 7505 3). Any DNS error, no MX at all
// or an ordinary MX among the records means it does not. DNS errors are not cached.
func isNullMX(ctx context.Context, domain string) bool {
	now := time.Now()
	nullMXCache.Lock()
	e, ok := nullMXCache.m[domain]
	nullMXCache.Unlock()
	if ok && now.Before(e.until) {
		return e.null
	}
	ctx, cancel := context.WithTimeout(ctx, senderNullMXTimeout)
	defer cancel()
	records, err := lookupMX(ctx, domain)
	var dnsErr *net.DNSError
	if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		return false
	}
	null := len(records) > 0
	for _, r := range records {
		if strings.TrimSuffix(r.Host, ".") != "" {
			null = false
			break
		}
	}
	nullMXCache.Lock()
	if len(nullMXCache.m) >= nullMXCacheSize {
		for d, old := range nullMXCache.m {
			if !now.Before(old.until) {
				delete(nullMXCache.m, d)
			}
		}
		if len(nullMXCache.m) >= nullMXCacheSize {
			nullMXCache.m = map[string]nullMXEntry{}
		}
	}
	nullMXCache.m[domain] = nullMXEntry{null: null, until: now.Add(nullMXCacheTTL)}
	nullMXCache.Unlock()
	return null
}
