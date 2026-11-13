package revocation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert, key}
}

func (ca testCA) leaf(t *testing.T, serial int64, crlURL string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "mx.example.com"},
		CRLDistributionPoints: []string{crlURL}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func (ca testCA) crl(t *testing.T, next time.Time, revoked ...int64) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: next.Add(-2 * time.Hour), NextUpdate: next}
	for _, s := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: time.Now().Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// serve publishes body at a test URL and counts the fetches.
func serve(t *testing.T, body []byte, status int) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/ca.crl", &hits
}

// RFC 9325 7.5: a certificate in its issuer's CRL is refused; others pass; the CRL is cached.
func TestCheckRevoked(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "Test CA")
	url, hits := serve(t, ca.crl(t, time.Now().Add(time.Hour), 7), http.StatusOK)
	c := New(true)
	if err := c.Check([]*x509.Certificate{ca.leaf(t, 7, url), ca.cert}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked serial: %v", err)
	}
	if err := c.Check([]*x509.Certificate{ca.leaf(t, 8, url), ca.cert}); err != nil {
		t.Fatalf("good serial: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("%d fetches, want 1 (cached)", hits.Load())
	}
}

// Soft-fail: an unreachable, foreign-signed or stale CRL proves nothing, so the certificate passes.
func TestCheckSoftFails(t *testing.T) {
	t.Parallel()
	ca, other := newCA(t, "Test CA"), newCA(t, "Other CA")
	down, _ := serve(t, nil, http.StatusNotFound)
	forged, _ := serve(t, other.crl(t, time.Now().Add(time.Hour), 7), http.StatusOK) // not signed by the issuer
	stale, _ := serve(t, ca.crl(t, time.Now().Add(-time.Minute), 7), http.StatusOK)
	junk, _ := serve(t, []byte("not a crl"), http.StatusOK)
	for name, url := range map[string]string{"down": down, "forged": forged, "stale": stale, "junk": junk} {
		if err := New(true).Check([]*x509.Certificate{ca.leaf(t, 7, url), ca.cert}); err != nil {
			t.Errorf("%s: %v; want soft-fail", name, err)
		}
	}
}

// The default checker never fetches a CRL from an internal address (SSRF).
func TestDefaultRefusesInternalCRLHost(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "Test CA")
	url, hits := serve(t, ca.crl(t, time.Now().Add(time.Hour), 7), http.StatusOK)
	if err := New(false).Check([]*x509.Certificate{ca.leaf(t, 7, url), ca.cert}); err != nil || hits.Load() != 0 {
		t.Fatalf("err %v, %d fetches; want no fetch and soft-fail", err, hits.Load())
	}
}
