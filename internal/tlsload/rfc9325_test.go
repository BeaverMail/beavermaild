package tlsload_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/tlsload"
	"github.com/BeaverMail/beavermaild/internal/tlsload/tlstest"
)

func handshake(t *testing.T, server *tls.Config, client *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	srv := tls.Server(a, server)
	go func() { _ = srv.Handshake() }()
	c := tls.Client(b, client)
	err := c.Handshake()
	return c.ConnectionState(), err
}

func loadTest(t *testing.T) *tlsload.Certs {
	t.Helper()
	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"mail.example.com"})
	certs, err := tlsload.Load(certFile, keyFile, "1.2")
	if err != nil {
		t.Fatal(err)
	}
	return certs
}

// RFC 9325 4.2: CBC suites only with encrypt_then_mac, which crypto/tls lacks: the server offers AEAD only.
func TestServerRefusesCBC(t *testing.T) {
	t.Parallel()
	cfg := loadTest(t).Config()
	cbc := &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}}
	if _, err := handshake(t, cfg, cbc); err == nil {
		t.Fatal("CBC suite negotiated")
	}
	gcm := &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}
	if _, err := handshake(t, cfg, gcm); err != nil {
		t.Fatalf("AES-GCM refused: %v", err)
	}
}

// RFC 9325 3.8 (ALPACA): a listener for one protocol refuses a client offering only another one;
// clients without ALPN still connect.
func TestWithALPN(t *testing.T) {
	t.Parallel()
	cfg := loadTest(t).WithALPN("imap").Config()
	if _, err := handshake(t, cfg, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}); err == nil {
		t.Fatal("HTTP client accepted by the IMAP listener")
	}
	if st, err := handshake(t, cfg, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"imap"}}); err != nil || st.NegotiatedProtocol != "imap" {
		t.Fatalf("IMAP client: %q %v", st.NegotiatedProtocol, err)
	}
	if _, err := handshake(t, cfg, &tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("client without ALPN: %v", err)
	}
}

// RFC 9325 4.5: no RSA key under 2048 bits, no SHA-1 signature, for server certificates.
func TestCheckServerCert(t *testing.T) {
	t.Parallel()
	mk := func(key any, pub any, alg x509.SignatureAlgorithm) (certPEM, keyPEM []byte) {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.example.com"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), SignatureAlgorithm: alg}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
		if err != nil {
			t.Skipf("cannot build the test certificate: %v", err)
		}
		k, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if c, k := mk(ec, &ec.PublicKey, x509.ECDSAWithSHA256); tlsload.CheckKeyPair(c, k) != nil {
		t.Fatal("ECDSA P-256 SHA-256 refused")
	}
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	if c, k := mk(rsa2048, &rsa2048.PublicKey, x509.SHA256WithRSA); tlsload.CheckKeyPair(c, k) != nil {
		t.Fatal("RSA 2048 refused")
	}
	if c, k := mk(rsa2048, &rsa2048.PublicKey, x509.SHA1WithRSA); tlsload.CheckKeyPair(c, k) == nil {
		t.Fatal("SHA-1 signature accepted")
	}
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if c, k := mk(rsa1024, &rsa1024.PublicKey, x509.SHA256WithRSA); tlsload.CheckKeyPair(c, k) == nil {
		t.Fatal("RSA 1024 accepted")
	}
	if tlsload.CheckKeyPair([]byte("junk"), []byte("junk")) == nil {
		t.Fatal("unparsable pair accepted")
	}
}
