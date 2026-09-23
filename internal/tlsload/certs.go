// TLS certificate loading for SMTP and IMAP listeners.
package tlsload

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
)

// Certs holds a loaded server certificate and shared tls.Config.
type Certs struct {
	cfg *tls.Config
}

// FromConfig wraps an existing tls.Config (e.g. with GetCertificate).
func FromConfig(cfg *tls.Config) *Certs {
	if cfg == nil {
		return nil
	}
	return &Certs{cfg: cfg}
}

// Load reads cert and key PEM files and builds a server tls.Config.
func Load(certFile, keyFile, minVersion string) (*Certs, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsload: load key pair: %w", err)
	}
	ver, err := parseMinVersion(minVersion)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   ver,
	}
	return &Certs{cfg: cfg}, nil
}

// Config returns the shared tls.Config (do not mutate).
func (c *Certs) Config() *tls.Config {
	if c == nil {
		return nil
	}
	return c.cfg
}

// Listen binds a TLS listener on addr (implicit TLS).
func (c *Certs) Listen(network, addr string) (net.Listener, error) {
	if c == nil || c.cfg == nil {
		return nil, fmt.Errorf("tlsload: no certificate loaded")
	}
	return tls.Listen(network, addr, c.cfg)
}

// WrapServer upgrades a TCP connection to TLS server mode.
func (c *Certs) WrapServer(conn net.Conn) *tls.Conn {
	return tls.Server(conn, c.cfg)
}

func parseMinVersion(v string) (uint16, error) {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("tlsload: unsupported min_version %q", v)
	}
}

// FileReadable reports whether both PEM paths exist.
func FileReadable(certFile, keyFile string) bool {
	if certFile == "" || keyFile == "" {
		return false
	}
	if _, err := os.Stat(certFile); err != nil {
		return false
	}
	if _, err := os.Stat(keyFile); err != nil {
		return false
	}
	return true
}
