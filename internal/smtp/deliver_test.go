package smtp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/mtasts"
	"github.com/BeaverMail/beavermaild/internal/revocation"
	"github.com/BeaverMail/beavermaild/internal/tlsload/tlstest"
)

func TestDeliverMXPermanentStops(t *testing.T) {
	t.Parallel()
	first := startMockMX(t, mxScript{
		onRCPT: "550 5.1.1 unknown\r\n",
	})
	second := startMockMX(t, mxScript{
		onRCPT: "250 OK\r\n",
	})
	t.Cleanup(func() { first.close(); second.close() })

	_, err := deliverMX(context.Background(), []string{first.addr, second.addr}, "a@b.c", "x@y.z", []byte("hi\r\n"), ClientOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	var re *ResponseError
	if !errors.As(err, &re) || re.Code != 550 {
		t.Fatalf("got %v", err)
	}
	if second.accepted() {
		t.Fatal("second mx should not be tried on 550")
	}
}

func TestDeliverMX421TriesNext(t *testing.T) {
	t.Parallel()
	first := startMockMX(t, mxScript{
		onRCPT: "421 closing\r\n",
	})
	second := startMockMX(t, mxScript{})
	t.Cleanup(func() { first.close(); second.close() })

	_, err := deliverMX(context.Background(), []string{first.addr, second.addr}, "a@b.c", "x@y.z", []byte("hi\r\n"), ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !second.accepted() {
		t.Fatal("second mx should deliver")
	}
}

func TestDeliverMXDialFailTriesNext(t *testing.T) {
	t.Parallel()
	second := startMockMX(t, mxScript{})
	t.Cleanup(second.close)

	_, err := deliverMX(context.Background(), []string{"127.0.0.1:1", second.addr}, "a@b.c", "x@y.z", []byte("hi\r\n"), ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !second.accepted() {
		t.Fatal("second mx should deliver after dial fail")
	}
}

func TestFilterMXForMTASTS(t *testing.T) {
	t.Parallel()
	policy := &mtasts.Policy{
		Mode: mtasts.ModeEnforce,
		MX:   []string{"mx.ok.test"},
	}
	hosts, err := filterMXForMTASTS([]string{"mx.ok.test:25", "mx.bad.test:25"}, policy)
	if err != nil || len(hosts) != 1 || hosts[0] != "mx.ok.test:25" {
		t.Fatalf("hosts %v err %v", hosts, err)
	}
	_, err = filterMXForMTASTS([]string{"mx.bad.test:25"}, policy)
	if err == nil || deliveryPermanent(err) {
		t.Fatalf("got %v; want a transient no matching mx error (RFC 8461 5)", err)
	}
}

func TestDeliverMXMTASTSEnforceRequiresSTARTTLS(t *testing.T) {
	t.Parallel()
	mx := startMockMX(t, mxScript{})
	t.Cleanup(mx.close)

	host, _, _ := net.SplitHostPort(mx.addr)
	policy := &mtasts.Policy{
		Mode: mtasts.ModeEnforce,
		MX:   []string{strings.ToLower(host)},
	}
	_, err := deliverMX(context.Background(), []string{mx.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), mxOptionsForPolicy(ClientOptions{}, policy, "", "example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	if deliveryPermanent(err) {
		t.Fatalf("got permanent %v; RFC 8461 5: retry, rechecking the policy", err)
	}
}

// wrongNameTLS is a self-signed certificate for another host, as the MX of a hosting provider
// presents (*.provider.example for mx.customer.example).
func wrongNameTLS(t *testing.T, minV, maxV uint16) *tls.Config {
	t.Helper()
	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"mx.provider.example"})
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: minV, MaxVersion: maxV}
}

// RFC 7435 3: without a policy the MX certificate is not checked, so a certificate for another name
// still gets the message delivered, encrypted. Before: x509 error, retried until the queue gave up.
func TestDeliverMXOpportunisticTLSIgnoresCertificate(t *testing.T) {
	t.Parallel()
	for _, mode := range []mtasts.Mode{"", mtasts.ModeTesting, mtasts.ModeNone} {
		mx := startMockMX(t, mxScript{advertiseSTARTTLS: true, tls: wrongNameTLS(t, tls.VersionTLS12, 0)})
		var policy *mtasts.Policy
		if mode != "" {
			policy = &mtasts.Policy{Mode: mode, MX: []string{"other.example"}}
		}
		_, err := deliverMX(context.Background(), []string{mx.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), mxOptionsForPolicy(ClientOptions{}, policy, "", "example.com"))
		mx.close()
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
	}
}

// RFC 8996 2-3: TLS 1.0 and 1.1 MUST NOT be negotiated, opportunistic TLS included. An MX that offers
// nothing newer is unusable: the next MX is tried and the failure stays transient (never in clear).
func TestDeliverMXRefusesTLS10(t *testing.T) {
	t.Parallel()
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		first := startMockMX(t, mxScript{advertiseSTARTTLS: true, tls: wrongNameTLS(t, v, v)})
		second := startMockMX(t, mxScript{})
		_, err := deliverMX(context.Background(), []string{first.addr, second.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), mxOptionsForPolicy(ClientOptions{}, nil, "", "example.com"))
		first.close()
		second.close()
		if err != nil {
			t.Fatalf("TLS %x: %v; want delivery through the next MX", v, err)
		}
		if !second.accepted() {
			t.Fatalf("TLS %x: next MX not tried", v)
		}
	}
}

// RFC 8461 4.2, 5, 5.1: under enforce a certificate that does not validate makes the MX unusable: the
// next MX is tried and the failure stays transient.
func TestDeliverMXEnforceBadCertificateTriesNext(t *testing.T) {
	t.Parallel()
	first := startMockMX(t, mxScript{advertiseSTARTTLS: true, tls: wrongNameTLS(t, tls.VersionTLS12, 0)})
	second := startMockMX(t, mxScript{})
	t.Cleanup(func() { first.close(); second.close() })
	policy := &mtasts.Policy{Mode: mtasts.ModeEnforce, MX: []string{"127.0.0.1"}}
	_, err := deliverMX(context.Background(), []string{first.addr, second.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), mxOptionsForPolicy(ClientOptions{}, policy, "", "example.com"))
	if err == nil || deliveryPermanent(err) {
		t.Fatalf("got %v; want a transient failure", err)
	}
	if !second.accepted() {
		t.Fatal("second MX not tried")
	}
}

type mxScript struct {
	onRCPT            string
	advertiseSTARTTLS bool
	tls               *tls.Config // STARTTLS really upgrades with this config (nil: 220 and stay plain)
	startTLSReply     string      // reply refusing STARTTLS (the session stays in clear)
}

type mockMX struct {
	addr string
	ln   net.Listener
	done chan struct{}
	hit  bool
}

func startMockMX(t *testing.T, script mxScript) *mockMX {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &mockMX{addr: ln.Addr().String(), ln: ln, done: make(chan struct{})}
	if script.onRCPT == "" {
		script.onRCPT = "250 OK\r\n"
	}
	go func() {
		defer close(m.done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		m.hit = true
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		writeSMTP(conn, "220 mx.test ESMTP\r\n")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "EHLO"):
				if script.advertiseSTARTTLS {
					writeSMTP(conn, "250-mx.test\r\n250-STARTTLS\r\n250 OK\r\n")
				} else {
					writeSMTP(conn, "250-mx.test\r\n250 OK\r\n")
				}
			case strings.HasPrefix(line, "STARTTLS") && script.startTLSReply != "":
				writeSMTP(conn, script.startTLSReply)
				if strings.HasPrefix(script.startTLSReply, "421") {
					return
				}
			case strings.HasPrefix(line, "STARTTLS"):
				writeSMTP(conn, "220 ready\r\n")
				if script.tls != nil {
					tc := tls.Server(conn, script.tls)
					defer tc.Close()
					conn, r, script.advertiseSTARTTLS = tc, bufio.NewReader(tc), false
				}
			case strings.HasPrefix(line, "MAIL"):
				writeSMTP(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "RCPT"):
				writeSMTP(conn, script.onRCPT)
				if strings.HasPrefix(script.onRCPT, "550") || strings.HasPrefix(script.onRCPT, "421") {
					return
				}
			case line == "DATA":
				inData = true
				writeSMTP(conn, "354 go\r\n")
			default:
				if inData {
					if line == "." {
						inData = false
						writeSMTP(conn, "250 queued\r\n")
					}
					continue
				}
				if strings.HasPrefix(line, "QUIT") {
					writeSMTP(conn, "221 bye\r\n")
					return
				}
			}
		}
	}()
	return m
}

func (m *mockMX) close() { _ = m.ln.Close(); <-m.done }
func (m *mockMX) accepted() bool {
	select {
	case <-m.done:
		return m.hit
	default:
		return m.hit
	}
}

func writeSMTP(conn net.Conn, s string) { _, _ = fmt.Fprint(conn, s) }

// RFC 8461 3.4: through a smart host, the smart host's domain is the Policy Domain.
func TestRelayOptionsForPolicy(t *testing.T) {
	t.Parallel()
	resolver := func(mode string) *mtasts.Resolver {
		return mtasts.NewResolver().
			WithTXTLookup(func(context.Context, string) ([]string, error) { return []string{"v=STSv1; id=one"}, nil }).
			WithPolicyFetcher(func(_ context.Context, domain string) ([]byte, error) {
				if domain != "relay.example.net" {
					return nil, fmt.Errorf("policy fetched for %q", domain)
				}
				return []byte("version: STSv1\nmode: " + mode + "\nmx: relay.example.net\nmax_age: 3600\n"), nil
			})
	}
	base := ClientOptions{TLSInsecureSkipVerify: true, User: "u", Password: "p"}
	opts, err := relayOptionsForPolicy(context.Background(), RemoteConfig{Relay: "relay.example.net:587", RelayOptions: base, MTASTS: resolver("enforce")})
	if err != nil || !opts.STARTTLS || !opts.RequireTLS || opts.TLSInsecureSkipVerify || opts.User != "u" {
		t.Fatalf("enforce: %+v %v; want STARTTLS required and verified", opts, err)
	}
	opts, err = relayOptionsForPolicy(context.Background(), RemoteConfig{Relay: "relay.example.net:587", RelayOptions: base, MTASTS: resolver("testing")})
	if err != nil || opts != base {
		t.Fatalf("testing: %+v %v; want the relay settings unchanged", opts, err)
	}
	for _, relay := range []string{"192.0.2.1:25", "localhost:25", "127.0.0.1:2525"} {
		opts, err = relayOptionsForPolicy(context.Background(), RemoteConfig{Relay: relay, RelayOptions: base, MTASTS: resolver("enforce")})
		if err != nil || opts != base {
			t.Fatalf("%s: %+v %v; address literals and loopback have no policy", relay, opts, err)
		}
	}
	other := mtasts.NewResolver().
		WithTXTLookup(func(context.Context, string) ([]string, error) { return []string{"v=STSv1; id=one"}, nil }).
		WithPolicyFetcher(func(context.Context, string) ([]byte, error) {
			return []byte("version: STSv1\nmode: enforce\nmx: mx.example.net\nmax_age: 3600\n"), nil
		})
	_, err = relayOptionsForPolicy(context.Background(), RemoteConfig{Relay: "relay.example.net:587", RelayOptions: base, MTASTS: other})
	if err == nil || deliveryPermanent(err) {
		t.Fatalf("non-matching smart host: %v; want a transient failure", err)
	}
}

// RFC 7435 3, 4: an MX that advertises STARTTLS and then refuses it keeps the session in clear; without
// a policy the message goes on in clear. 421 closes the session (next MX); under enforce it never goes
// in clear. Before: 4xx retried and 5xx bounced until the queue gave up.
func TestDeliverMXSTARTTLSRefusedContinuesInClear(t *testing.T) {
	t.Parallel()
	for _, reply := range []string{"454 4.7.0 TLS not available\r\n", "502 5.5.1 not implemented\r\n"} {
		mx := startMockMX(t, mxScript{advertiseSTARTTLS: true, startTLSReply: reply})
		_, err := deliverMX(context.Background(), []string{mx.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), mxOptionsForPolicy(ClientOptions{}, nil, "", "example.com"))
		mx.close()
		if err != nil {
			t.Fatalf("%q: %v", reply, err)
		}
	}

	first := startMockMX(t, mxScript{advertiseSTARTTLS: true, startTLSReply: "421 4.3.2 closing\r\n"})
	second := startMockMX(t, mxScript{})
	_, err := deliverMX(context.Background(), []string{first.addr, second.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), mxOptionsForPolicy(ClientOptions{}, nil, "", "example.com"))
	first.close()
	second.close()
	if err != nil {
		t.Fatalf("421: %v; want delivery through the next MX", err)
	}

	mx := startMockMX(t, mxScript{advertiseSTARTTLS: true, startTLSReply: "454 4.7.0 TLS not available\r\n"})
	t.Cleanup(mx.close)
	policy := &mtasts.Policy{Mode: mtasts.ModeEnforce, MX: []string{"127.0.0.1"}}
	_, err = deliverMX(context.Background(), []string{mx.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), mxOptionsForPolicy(ClientOptions{}, policy, "", "example.com"))
	if err == nil || deliveryPermanent(err) {
		t.Fatalf("enforce: %v; want a transient failure, never clear", err)
	}
}

// RFC 3207 6: TLS required for a selected destination (smtp.tls_policy). "encrypt" needs STARTTLS but
// not a valid certificate; "verify" needs both; neither ever goes in clear, not even after a refused
// STARTTLS.
func TestDeliverMXStaticTLSPolicy(t *testing.T) {
	t.Parallel()
	deliver := func(script mxScript, level string) error {
		mx := startMockMX(t, script)
		defer mx.close()
		_, err := deliverMX(context.Background(), []string{mx.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), mxOptionsForPolicy(ClientOptions{}, nil, level, "example.com"))
		return err
	}
	badCert := mxScript{advertiseSTARTTLS: true, tls: wrongNameTLS(t, tls.VersionTLS12, 0)}
	if err := deliver(badCert, TLSEncrypt); err != nil {
		t.Fatalf("encrypt, unverifiable certificate: %v", err)
	}
	for name, tc := range map[string]struct {
		script mxScript
		level  string
	}{
		"encrypt, no STARTTLS":      {mxScript{}, TLSEncrypt},
		"encrypt, STARTTLS refused": {mxScript{advertiseSTARTTLS: true, startTLSReply: "454 4.7.0 no\r\n"}, TLSEncrypt},
		"encrypt, TLS 1.0 only":     {mxScript{advertiseSTARTTLS: true, tls: wrongNameTLS(t, tls.VersionTLS10, tls.VersionTLS10)}, TLSEncrypt},
		"verify, bad certificate":   {badCert, TLSVerify},
	} {
		if err := deliver(tc.script, tc.level); err == nil || deliveryPermanent(err) {
			t.Errorf("%s: %v; want a transient failure", name, err)
		}
	}
	cfg := RemoteConfig{TLSPolicy: map[string]string{"xn--mnchen-3ya.example": TLSVerify}}
	if got := cfg.tlsLevel("MÜNCHEN.example."); got != TLSVerify {
		t.Fatalf("tlsLevel of a U-label domain: %q", got)
	}
}

// RFC 9325 4.2 and 5.2: an MX offering only a CBC suite still gets opportunistic mail, but not mail
// sent under a TLS policy, which uses AEAD suites only.
func TestDeliverMXCBCOnlyOpportunistic(t *testing.T) {
	t.Parallel()
	cbcOnly := func() *tls.Config {
		c := wrongNameTLS(t, tls.VersionTLS12, tls.VersionTLS12)
		c.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
		return c
	}
	mx := startMockMX(t, mxScript{advertiseSTARTTLS: true, tls: cbcOnly()})
	_, err := deliverMX(context.Background(), []string{mx.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), mxOptionsForPolicy(ClientOptions{}, nil, "", "example.com"))
	mx.close()
	if err != nil {
		t.Fatalf("opportunistic: %v", err)
	}
	mx = startMockMX(t, mxScript{advertiseSTARTTLS: true, tls: cbcOnly()})
	t.Cleanup(mx.close)
	_, err = deliverMX(context.Background(), []string{mx.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), mxOptionsForPolicy(ClientOptions{}, nil, TLSEncrypt, "example.com"))
	if err == nil || deliveryPermanent(err) {
		t.Fatalf("encrypt: %v; want a transient failure", err)
	}
}

// RFC 9325 7.1: "secure" checks the certificate against the recipient domain and its subdomains,
// with a trusted chain, never against the MX name from DNS.
func TestVerifyForDomain(t *testing.T) {
	t.Parallel()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(names ...string) tls.ConnectionState {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
	}
	for _, tc := range []struct {
		names []string
		roots *x509.CertPool
		ok    bool
	}{
		{[]string{"example.com"}, roots, true},
		{[]string{"mx1.example.com"}, roots, true},
		{[]string{"*.example.com"}, roots, true},
		{[]string{"mx.hosting.example.net"}, roots, false}, // valid for the MX name only
		{[]string{"notexample.com"}, roots, false},
		{[]string{"mx1.example.com"}, x509.NewCertPool(), false}, // untrusted chain
	} {
		_, err := verifyForDomain(leaf(tc.names...), "example.com", tc.roots)
		if (err == nil) != tc.ok {
			t.Errorf("%v: %v, want ok=%v", tc.names, err, tc.ok)
		}
	}
	if opts := mxOptionsForPolicy(ClientOptions{}, nil, TLSSecure, "example.com"); !opts.RequireTLS || opts.VerifyDomain != "example.com" {
		t.Fatalf("secure options %+v", opts)
	}
}

// RFC 9325 7.5: a verified MX whose certificate its CA has revoked is refused (next MX, transient).
func TestDeliverMXRevokedCertificate(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(66), RevocationTime: time.Now()}}}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	crlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(crlDER) }))
	t.Cleanup(crlSrv.Close)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(66),
		Subject: pkix.Name{CommonName: "mx1.example.com"}, DNSNames: []string{"mx1.example.com"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CRLDistributionPoints: []string{crlSrv.URL + "/ca.crl"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}, ca, &leafKey.PublicKey, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	revocationChecker = revocation.New(true) // the CRL server is on loopback
	t.Cleanup(func() { revocationChecker = revocation.Default })

	mx := startMockMX(t, mxScript{advertiseSTARTTLS: true, tls: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}})
	t.Cleanup(mx.close)
	opts := mxOptionsForPolicy(ClientOptions{}, nil, TLSSecure, "example.com")
	opts.rootCAs = roots
	_, err = deliverMX(context.Background(), []string{mx.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), opts)
	if !errors.Is(err, revocation.ErrRevoked) || deliveryPermanent(err) {
		t.Fatalf("got %v; want a transient revoked-certificate failure", err)
	}
}
