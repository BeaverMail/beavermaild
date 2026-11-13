// Package revocation is the strategy RFC 9325 7.5 requires (MUST) to distrust revoked certificates on
// the TLS connections that verify the peer: CRLs from the certificates' distribution points, cached
// until their nextUpdate. crypto/x509 checks no revocation itself.
//
// It soft-fails: a CRL that cannot be fetched, parsed, authenticated or is stale proves nothing, and
// the certificate is accepted, as browsers do with OCSP (RFC 9325 7.5). Only a CRL signed by the
// issuer that lists the serial rejects a certificate. Let's Encrypt ended OCSP in 2025 and publishes
// CRLs, so OCSP is not used.
package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/BeaverMail/beavermaild/internal/security"
)

const (
	fetchTimeout = 10 * time.Second
	maxCRLBytes  = 16 << 20 // large CAs shard their CRLs; this bounds memory per fetch
	maxEntries   = 1000     // CRL URLs come from trusted CA certificates, so few; bound them anyway
	retryAfter   = 10 * time.Minute
	defaultTTL   = 24 * time.Hour // a CRL without nextUpdate
	maxTTL       = 7 * 24 * time.Hour
)

// ErrRevoked is returned for a certificate listed in its issuer's CRL.
var ErrRevoked = errors.New("revocation: certificate revoked")

// Checker fetches and caches CRLs.
type Checker struct {
	client *http.Client
	now    func() time.Time

	mu    sync.Mutex
	cache map[string]*entry // by CRL URL
}

type entry struct {
	revoked map[string]bool // serial numbers, decimal; nil when the CRL is unusable
	until   time.Time       // cache expiry
}

// Default is the process-wide checker; CRL hosts on internal addresses are refused (SSRF).
var Default = New(false)

// New returns a checker; allowPrivate lets CRL hosts resolve to internal addresses (tests).
func New(allowPrivate bool) *Checker {
	dialer := &net.Dialer{Timeout: fetchTimeout}
	if !allowPrivate {
		dialer.Control = security.RejectInternalDial
	}
	return &Checker{
		client: &http.Client{
			Timeout:   fetchTimeout,
			Transport: &http.Transport{DialContext: dialer.DialContext, Proxy: nil},
		},
		now:   time.Now,
		cache: make(map[string]*entry),
	}
}

// Check rejects a verified chain (leaf first, root last) whose leaf or intermediates are revoked.
func (c *Checker) Check(chain []*x509.Certificate) error {
	for i := 0; i+1 < len(chain); i++ {
		cert, issuer := chain[i], chain[i+1]
		for _, url := range cert.CRLDistributionPoints {
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				continue // e.g. ldap://
			}
			revoked := c.list(url, issuer)
			if revoked == nil {
				continue // unusable: try the next distribution point, else soft-fail
			}
			if revoked[cert.SerialNumber.String()] {
				return fmt.Errorf("%w: %s (serial %s)", ErrRevoked, cert.Subject, cert.SerialNumber)
			}
			break
		}
	}
	return nil
}

// list returns the revoked serials of the CRL at url signed by issuer, nil when it is unusable.
func (c *Checker) list(url string, issuer *x509.Certificate) map[string]bool {
	now := c.now()
	c.mu.Lock()
	if e := c.cache[url]; e != nil && now.Before(e.until) {
		c.mu.Unlock()
		return e.revoked
	}
	c.mu.Unlock()

	e := &entry{until: now.Add(retryAfter)}
	if crl, err := c.fetch(url); err == nil && bytes.Equal(crl.RawIssuer, issuer.RawSubject) &&
		crl.CheckSignatureFrom(issuer) == nil && (crl.NextUpdate.IsZero() || now.Before(crl.NextUpdate)) {
		e.revoked = make(map[string]bool, len(crl.RevokedCertificateEntries))
		for _, r := range crl.RevokedCertificateEntries {
			e.revoked[r.SerialNumber.String()] = true
		}
		e.until = now.Add(defaultTTL)
		if !crl.NextUpdate.IsZero() {
			e.until = crl.NextUpdate
		}
		if e.until.After(now.Add(maxTTL)) {
			e.until = now.Add(maxTTL)
		}
	}
	c.mu.Lock()
	if len(c.cache) >= maxEntries {
		for u, old := range c.cache {
			if !now.Before(old.until) {
				delete(c.cache, u)
			}
		}
	}
	if len(c.cache) < maxEntries {
		c.cache[url] = e
	}
	c.mu.Unlock()
	return e.revoked
}

func (c *Checker) fetch(url string) (*x509.RevocationList, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("revocation: %s: status %d", url, resp.StatusCode)
	}
	der, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLBytes+1))
	if err != nil {
		return nil, err
	}
	if len(der) > maxCRLBytes {
		return nil, fmt.Errorf("revocation: %s: CRL over %d bytes", url, maxCRLBytes)
	}
	return x509.ParseRevocationList(der)
}
