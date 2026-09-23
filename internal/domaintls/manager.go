// Per-domain TLS: custom PEM files and ACME HTTP-01 via autocert.
package domaintls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/acme/autocert"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/tlsload"
)

// Manager resolves certificates by SNI for per-domain custom and ACME hosts.
type Manager struct {
	mu       sync.RWMutex
	dir      *directory.Local
	dataDir  string
	acme     *autocert.Manager
	fallback *tls.Config
	custom   map[string]*tls.Certificate // mail hostname → cert
}

// New builds a manager. fallback may be nil. ACME cache is under dataDir/tls/acme-domains.
func New(dir *directory.Local, dataDir string, fallback *tlsload.Certs, minVersion string) (*Manager, error) {
	m := &Manager{
		dir:     dir,
		dataDir: dataDir,
		custom:  make(map[string]*tls.Certificate),
	}
	if fallback != nil {
		m.fallback = fallback.Config()
	}
	cache := filepath.Join(dataDir, "tls", "acme-domains")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return nil, err
	}
	ver, err := parseMin(minVersion)
	if err != nil {
		return nil, err
	}
	m.acme = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cache),
		HostPolicy: m.hostPolicy,
	}
	_ = ver
	if err := m.Reload(context.Background()); err != nil {
		return nil, err
	}
	return m, nil
}

func parseMin(v string) (uint16, error) {
	switch strings.TrimSpace(v) {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("domaintls: unsupported min_version %q", v)
	}
}

func (m *Manager) hostPolicy(ctx context.Context, host string) error {
	if m.dir == nil {
		return fmt.Errorf("domaintls: no directory")
	}
	dom, err := m.dir.LookupDomainByMailHost(ctx, host)
	if err != nil {
		return err
	}
	if dom.SSLMode != storage.DomainSSLACME {
		return fmt.Errorf("domaintls: host %q not acme", host)
	}
	return nil
}

// HTTPHandler serves ACME HTTP-01 challenges.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	if m == nil || m.acme == nil {
		return fallback
	}
	return m.acme.HTTPHandler(fallback)
}

// Reload refreshes custom certificates from disk for all domains.
func (m *Manager) Reload(ctx context.Context) error {
	if m == nil || m.dir == nil {
		return nil
	}
	domains, err := m.dir.ListDomains(ctx)
	if err != nil {
		return err
	}
	next := make(map[string]*tls.Certificate)
	for _, dom := range domains {
		host := strings.ToLower(strings.TrimSpace(dom.MailHostname))
		if host == "" || dom.SSLMode != storage.DomainSSLCustom {
			continue
		}
		certPath := directory.DomainTLSCertPath(m.dataDir, dom.ID)
		keyPath := directory.DomainTLSKeyPath(m.dataDir, dom.ID)
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			continue
		}
		c := cert
		next[host] = &c
	}
	m.mu.Lock()
	m.custom = next
	m.mu.Unlock()
	return nil
}

// TLSConfig returns a config with GetCertificate for SNI (custom + ACME + fallback).
func (m *Manager) TLSConfig() *tls.Config {
	if m == nil {
		return nil
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.getCertificate,
	}
	if m.fallback != nil && m.fallback.MinVersion != 0 {
		cfg.MinVersion = m.fallback.MinVersion
	}
	return cfg
}

func (m *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.ToLower(strings.TrimSpace(hello.ServerName))
	m.mu.RLock()
	c := m.custom[host]
	m.mu.RUnlock()
	if c != nil {
		return c, nil
	}
	if m.acme != nil && host != "" {
		if cert, err := m.acme.GetCertificate(hello); err == nil {
			return cert, nil
		}
	}
	if m.fallback != nil && len(m.fallback.Certificates) > 0 {
		return &m.fallback.Certificates[0], nil
	}
	if m.acme != nil {
		return m.acme.GetCertificate(hello)
	}
	return nil, fmt.Errorf("domaintls: no certificate for %q", host)
}

// WrapCerts returns tlsload-compatible Certs using this manager's TLS config.
func (m *Manager) AsCerts() *tlsload.Certs {
	if m == nil {
		return nil
	}
	return tlsload.FromConfig(m.TLSConfig())
}
