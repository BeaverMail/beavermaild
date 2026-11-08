package domaintls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/tlsload/tlstest"
)

func newTestManager(t *testing.T, opts Options) *Manager {
	t.Helper()
	opts.ACMECacheDir = filepath.Join(t.TempDir(), "acme")
	m, err := New(nil, t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func leafName(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestSelfSignedCreatedOnceAndReused(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	opts := Options{ACMECacheDir: filepath.Join(dataDir, "acme")}
	m1, err := New(nil, dataDir, opts)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := New(nil, dataDir, opts)
	if err != nil {
		t.Fatal(err)
	}
	c1, _ := m1.getCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.com"})
	c2, _ := m2.getCertificate(&tls.ClientHelloInfo{})
	if c1 == nil || c2 == nil || string(c1.Certificate[0]) != string(c2.Certificate[0]) {
		t.Fatal("self-signed cert not reused across restarts")
	}
}

func TestGlobalPEMReloadsWhenChanged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certFile, keyFile := tlstest.WritePEM(t, dir, []string{"old.example.com"})
	m := newTestManager(t, Options{CertFile: certFile, KeyFile: keyFile})
	c, _ := m.getCertificate(&tls.ClientHelloInfo{ServerName: "old.example.com"})
	if leafName(t, c) != "old.example.com" {
		t.Fatalf("got %s", leafName(t, c))
	}

	tlstest.WritePEM(t, dir, []string{"new.example.com"})
	later := time.Now().Add(time.Minute)
	_ = os.Chtimes(certFile, later, later)
	m.global.checked = time.Time{} // skip the recheck delay
	c, _ = m.getCertificate(&tls.ClientHelloInfo{ServerName: "old.example.com"})
	if leafName(t, c) != "new.example.com" {
		t.Fatalf("not reloaded: %s", leafName(t, c))
	}
}

func TestBadGlobalPEMFailsStartup(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing.pem")
	if _, err := New(nil, t.TempDir(), Options{CertFile: missing, KeyFile: missing, ACMECacheDir: filepath.Join(t.TempDir(), "acme")}); err == nil {
		t.Fatal("expected error")
	}
}

func TestHostPolicyStaticHosts(t *testing.T) {
	t.Parallel()
	m := newTestManager(t, Options{ACMEHosts: []string{" Mail.Example.com "}})
	if err := m.hostPolicy(context.Background(), "mail.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := m.hostPolicy(context.Background(), "other.example.com"); err == nil {
		t.Fatal("expected refusal")
	}
}

// A client advertising an unrelated ALPN protocol (e.g. an IMAP client) must still complete the handshake.
func TestHandshakeWithForeignALPN(t *testing.T) {
	t.Parallel()
	m := newTestManager(t, Options{})
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	go func() { _ = tls.Server(srv, m.TLSConfig()).Handshake() }()
	c := tls.Client(cli, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"imap"}})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
}

func TestACMEALPNOnlyForValidators(t *testing.T) {
	t.Parallel()
	cfg := newTestManager(t, Options{}).TLSConfig()
	got, _ := cfg.GetConfigForClient(&tls.ClientHelloInfo{SupportedProtos: []string{"acme-tls/1"}})
	if got == nil || len(got.NextProtos) != 1 || got.NextProtos[0] != "acme-tls/1" {
		t.Fatalf("validator config %+v", got)
	}
	if got, _ := cfg.GetConfigForClient(&tls.ClientHelloInfo{SupportedProtos: []string{"h2", "http/1.1"}}); got != nil {
		t.Fatal("regular clients must use the base config")
	}
}
