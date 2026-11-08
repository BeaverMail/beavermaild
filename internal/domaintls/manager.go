// Package domaintls is the single certificate source for SMTP, IMAP and HTTP:
// per-domain custom PEM, ACME (tls.acme_hosts plus domains with ssl_mode acme),
// the global tls.cert_file (reloaded when it changes on disk), and a self-signed last resort.
package domaintls

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
)

// prefetchInterval re-checks ACME hosts: picks up new domains and retries failed issuance.
const prefetchInterval = time.Hour

// Options configures certificate sources.
type Options struct {
	// CertFile and KeyFile are the global PEM pair (absolute paths); empty disables it.
	CertFile string
	KeyFile  string
	// ACMEHosts are static hostnames issued via ACME besides per-domain ssl_mode acme.
	ACMEHosts []string
	// ACMECacheDir stores ACME account and certificates.
	ACMECacheDir string
	MinVersion   string
	Log          *slog.Logger
}

// Manager resolves certificates by SNI.
type Manager struct {
	dir        *directory.Local
	dataDir    string
	log        *slog.Logger
	minVersion uint16
	acmeHosts  map[string]bool
	acme       *autocert.Manager
	global     *fileCert
	self       *tls.Certificate
	kick       chan struct{}

	mu     sync.RWMutex
	custom map[string]*tls.Certificate // mail hostname → cert
	ready  map[string]bool             // ACME hosts with an issued certificate
}

// New builds a manager. A broken global PEM is a startup error.
func New(dir *directory.Local, dataDir string, opts Options) (*Manager, error) {
	ver, err := tlsload.ParseMinVersion(opts.MinVersion)
	if err != nil {
		return nil, err
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{
		dir:        dir,
		dataDir:    dataDir,
		log:        log,
		minVersion: ver,
		acmeHosts:  make(map[string]bool),
		kick:       make(chan struct{}, 1),
		custom:     make(map[string]*tls.Certificate),
		ready:      make(map[string]bool),
	}
	for _, h := range opts.ACMEHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			m.acmeHosts[h] = true
		}
	}
	if err := os.MkdirAll(opts.ACMECacheDir, 0o700); err != nil {
		return nil, err
	}
	m.acme = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(opts.ACMECacheDir),
		HostPolicy: m.hostPolicy,
	}
	if opts.CertFile != "" {
		if m.global, err = loadFileCert(opts.CertFile, opts.KeyFile); err != nil {
			return nil, err
		}
	} else if m.self, err = loadOrCreateSelfSigned(filepath.Join(dataDir, "tls", "self")); err != nil {
		return nil, err
	}
	if err := m.Reload(context.Background()); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) hostPolicy(ctx context.Context, host string) error {
	if m.acmeHosts[host] {
		return nil
	}
	if m.dir == nil {
		return errNotACME(host)
	}
	dom, err := m.dir.LookupDomainByMailHost(ctx, host)
	if err != nil {
		return err
	}
	if dom.SSLMode != storage.DomainSSLACME {
		return errNotACME(host)
	}
	return nil
}

// HTTPHandler serves ACME HTTP-01 challenges, passing other requests to fallback.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	if m == nil || m.acme == nil {
		return fallback
	}
	return m.acme.HTTPHandler(fallback)
}

// Reload refreshes custom certificates from disk and schedules ACME issuance for new hosts.
func (m *Manager) Reload(ctx context.Context) error {
	if m == nil {
		return nil
	}
	select {
	case m.kick <- struct{}{}:
	default:
	}
	if m.dir == nil {
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
		cert, err := tls.LoadX509KeyPair(directory.DomainTLSCertPath(m.dataDir, dom.ID), directory.DomainTLSKeyPath(m.dataDir, dom.ID))
		if err != nil {
			continue
		}
		next[host] = &cert
	}
	m.mu.Lock()
	m.custom = next
	m.mu.Unlock()
	return nil
}

// Run issues ACME certificates in the background until ctx is canceled: at start,
// after each Reload, and every prefetchInterval. Failures are logged, never fatal,
// so a host whose challenge is unreachable (e.g. behind a proxy) keeps the fallback cert.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(prefetchInterval)
	defer t.Stop()
	for {
		m.prefetch(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.kick:
		}
	}
}

func (m *Manager) prefetch(ctx context.Context) {
	hosts := m.acmeTargets(ctx)
	ready := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		if ctx.Err() != nil {
			return
		}
		// ECDSA suite so the cached cert matches what modern clients get in the handshake.
		_, err := m.acme.GetCertificate(&tls.ClientHelloInfo{
			ServerName:   host,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		})
		if err != nil {
			m.log.Warn("acme certificate", "host", host, "err", err)
			continue
		}
		ready[host] = true
	}
	m.mu.Lock()
	m.ready = ready
	m.mu.Unlock()
}

// acmeTargets lists static ACME hosts plus mail hostnames of ssl_mode acme domains.
func (m *Manager) acmeTargets(ctx context.Context) []string {
	var out []string
	for h := range m.acmeHosts {
		out = append(out, h)
	}
	if m.dir == nil {
		return out
	}
	domains, err := m.dir.ListDomains(ctx)
	if err != nil {
		m.log.Warn("acme list domains", "err", err)
		return out
	}
	for _, dom := range domains {
		host := strings.ToLower(strings.TrimSpace(dom.MailHostname))
		if host != "" && dom.SSLMode == storage.DomainSSLACME && !m.acmeHosts[host] {
			out = append(out, host)
		}
	}
	return out
}

// TLSConfig returns a server config resolving certificates by SNI.
func (m *Manager) TLSConfig() *tls.Config {
	if m == nil {
		return nil
	}
	cfg := &tls.Config{
		MinVersion:     m.minVersion,
		GetCertificate: m.getCertificate,
	}
	// acme-tls/1 is offered only to ACME validators: listing it for everyone would
	// make Go reject clients whose ALPN list does not overlap (e.g. IMAP clients).
	alpn := cfg.Clone()
	alpn.NextProtos = []string{acme.ALPNProto}
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if slices.Contains(hello.SupportedProtos, acme.ALPNProto) {
			return alpn, nil
		}
		return nil, nil
	}
	return cfg
}

// AsCerts returns tlsload-compatible Certs using this manager's TLS config.
func (m *Manager) AsCerts() *tlsload.Certs {
	if m == nil {
		return nil
	}
	return tlsload.FromConfig(m.TLSConfig())
}

// getCertificate order: ACME challenge, per-domain custom, issued ACME, global PEM, self-signed.
func (m *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if slices.Contains(hello.SupportedProtos, acme.ALPNProto) {
		return m.acme.GetCertificate(hello)
	}
	host := strings.ToLower(strings.TrimSpace(hello.ServerName))
	m.mu.RLock()
	c, ready := m.custom[host], m.ready[host]
	m.mu.RUnlock()
	if c != nil {
		return c, nil
	}
	// Only hosts already issued by prefetch: issuing inside a handshake would block the client.
	if ready {
		if cert, err := m.acme.GetCertificate(hello); err == nil {
			return cert, nil
		}
	}
	if m.global != nil {
		return m.global.get(m.log)
	}
	return m.self, nil
}
