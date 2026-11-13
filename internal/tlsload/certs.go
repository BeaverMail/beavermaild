// TLS certificate loading for SMTP and IMAP listeners.
package tlsload

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
// AEADSuites are the TLS 1.2 cipher suites used everywhere but opportunistic MX delivery: ECDHE with
// AES-GCM or ChaCha20-Poly1305 (RFC 9325 4.1, 4.2). CBC suites are left out: RFC 9325 4.2 allows them
// only with encrypt_then_mac, which crypto/tls does not implement. TLS 1.3 suites are all AEAD and not
// configurable.
var AEADSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// WithALPN returns a copy of c that negotiates only proto with ALPN (RFC 9325 3.8, 3.9): a client
// offering ALPN without proto gets no_application_protocol, so a connection meant for another service
// sharing the certificate (ALPACA) is refused. Clients sending no ALPN are unaffected.
func (c *Certs) WithALPN(proto string) *Certs {
	if c == nil || c.cfg == nil {
		return c
	}
	cfg := c.cfg.Clone()
	cfg.NextProtos = []string{proto}
	return &Certs{cfg: cfg}
}

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
	ver, err := ParseMinVersion(minVersion)
	if err != nil {
		return nil, err
	}
	if err := CheckServerCert(&cert); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   ver,
		CipherSuites: AEADSuites,
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

// ParseMinVersion maps tls.min_version ("", "1.2", "1.3") to a crypto/tls version.
func ParseMinVersion(v string) (uint16, error) {
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

// CheckServerCert refuses a server certificate RFC 9325 4.5 forbids: an RSA key under 2048 bits, or a
// leaf signed with SHA-1 or MD5.
func CheckServerCert(cert *tls.Certificate) error {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return errors.New("tlsload: no certificate")
		}
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return fmt.Errorf("tlsload: parse certificate: %w", err)
		}
	}
	if k, ok := leaf.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() < 2048 {
		return fmt.Errorf("tlsload: RSA key of %d bits, at least 2048 required (RFC 9325 4.5)", k.N.BitLen())
	}
	switch leaf.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return fmt.Errorf("tlsload: certificate signed with %s, SHA-1 and MD5 are not allowed (RFC 9325 4.5)", leaf.SignatureAlgorithm)
	}
	return nil
}

// CheckKeyPair parses a PEM certificate and key pair and checks it with CheckServerCert.
func CheckKeyPair(certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("tlsload: certificate and key: %w", err)
	}
	return CheckServerCert(&cert)
}
