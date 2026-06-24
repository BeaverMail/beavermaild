// ACME TLS-ALPN-01 certificate provisioning via golang.org/x/crypto/acme/autocert.
package tlsload

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/acme/autocert"
)

// LoadACME builds a tls.Config that obtains certs for hosts via TLS-ALPN-01.
func LoadACME(cacheDir string, hosts []string, minVersion string) (*Certs, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("tlsload: acme requires at least one host")
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("tlsload: acme cache: %w", err)
	}
	ver, err := parseMinVersion(minVersion)
	if err != nil {
		return nil, err
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(filepath.Clean(cacheDir)),
		HostPolicy: autocert.HostWhitelist(hosts...),
	}
	cfg := m.TLSConfig()
	cfg.MinVersion = ver
	return &Certs{cfg: cfg}, nil
}
