package dkimout

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
)

func TestSignAndVerify(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "dkim.pem")
	if err := GenerateTestKey(keyPath); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Selector: "beaver", Domain: "example.com", KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: hi\r\n\r\nbody\r\n")
	signed, err := s.Sign("alice@example.com", raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(signed, raw) {
		t.Fatal("expected signature added")
	}
	lower := strings.ToLower(string(signed))
	if !strings.Contains(lower, "dkim-signature:") || !strings.Contains(lower, "s=beaver") || !strings.Contains(lower, "d=example.com") {
		t.Fatalf("missing dkim header in %q", signed[:min(200, len(signed))])
	}
}

func TestSignDomainFromReturnPath(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "dkim.pem")
	if err := GenerateTestKey(keyPath); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Selector: "s1", KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: a@mail.test\r\n\r\nx\r\n")
	signed, err := s.Sign("sender@mail.test", raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(signed), "d=mail.test") {
		t.Fatalf("signed headers %q", signed[:min(120, len(signed))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// newSigner returns a signer for example.com with a fresh 2048-bit key and the TXT record serving it.
func newSigner(t *testing.T) (*Signer, string) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "dkim.pem")
	if err := GenerateKey(keyPath); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Selector: "beaver", Domain: "example.com", KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := PublicKeyDNS(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return s, rec
}

// verify checks every signature of msg against rec; it returns the results by domain.
func verify(t *testing.T, rec string, msg []byte) map[string]error {
	t.Helper()
	verifs, err := dkim.VerifyWithOptions(bytes.NewReader(msg), &dkim.VerifyOptions{
		LookupTXT: func(string) ([]string, error) { return []string{rec}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]error{}
	for _, v := range verifs {
		out[v.Domain] = v.Err
	}
	return out
}

// S1: a message carrying another server's s=beaver signature, or text about DKIM, is still signed.
// Before: the whole message was searched for "dkim-signature:" and "s=beaver" and signing skipped.
func TestSignDespiteForeignSignature(t *testing.T) {
	t.Parallel()
	s, rec := newSigner(t)
	raw := []byte("DKIM-Signature: v=1; a=rsa-sha256; d=other.example; s=beaver; h=from; bh=AAAA; b=AAAA\r\n" +
		"From: alice@example.com\r\nSubject: fwd\r\n\r\nour selector is s=beaver\r\n")
	signed, err := s.Sign("alice@example.com", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err, ok := verify(t, rec, signed)["example.com"]; !ok || err != nil {
		t.Fatalf("not signed for example.com: present %v, err %v", ok, err)
	}
}

// S2, S3, S4: relaxed canonicalization survives refolding; h= lists the core fields present, the
// single ones once more, never Received or client fields; an added From breaks the signature.
func TestSignHeaderSelection(t *testing.T) {
	t.Parallel()
	s, rec := newSigner(t)
	raw := []byte("Received: from client by mx.example.com\r\nX-Mailer: test\r\nFrom: alice@example.com\r\n" +
		"To: bob@example.org\r\nSubject: hello\r\nDate: Tue, 20 Oct 2026 12:00:00 +0000\r\n\r\nbody\r\n")
	signed, err := s.Sign("alice@example.com", raw)
	if err != nil {
		t.Fatal(err)
	}
	sig := strings.ToLower(string(signed[:bytes.Index(signed, []byte("Received:"))]))
	sig = strings.Join(strings.Fields(sig), "")
	if !strings.Contains(sig, "c=relaxed/relaxed") || !strings.Contains(sig, "h=from:from:subject:subject:date:date:to:to;") {
		t.Fatalf("signature %q", sig)
	}
	refolded := bytes.Replace(signed, []byte("Subject: hello"), []byte("Subject:   hello"), 1)
	if err, ok := verify(t, rec, refolded)["example.com"]; !ok || err != nil {
		t.Fatalf("refolded header broke the signature: %v", err)
	}
	added := bytes.Replace(signed, []byte("From: alice@example.com"), []byte("From: ceo@example.com\r\nFrom: alice@example.com"), 1)
	if err, ok := verify(t, rec, added)["example.com"]; ok && err == nil {
		t.Fatal("a From added in transit kept the signature valid")
	}
}

// S5: RFC 8301 3.2, no RSA key under 1024 bits. Before: it loaded, then every signing failed at
// delivery time (crypto/rsa refuses to sign with it).
func TestRejectShortRSAKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "short.pem")
	if err := os.WriteFile(path, rsa512PEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Selector: "s", Domain: "example.com", KeyPath: path}); err == nil || !strings.Contains(err.Error(), "512 bits") {
		t.Fatalf("got %v", err)
	}
}

// S6: RFC 8463 4, an ed25519 key gets a k=ed25519 record with the raw public key, and signs.
func TestEd25519KeyDNS(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ed.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := PublicKeyDNS(path)
	if err != nil || !strings.HasPrefix(rec, "v=DKIM1; k=ed25519; p=") {
		t.Fatalf("record %q err %v", rec, err)
	}
	s, err := New(Config{Selector: "ed", Domain: "example.com", KeyPath: path})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := s.Sign("alice@example.com", []byte("From: alice@example.com\r\n\r\nx\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err, ok := verify(t, rec, signed)["example.com"]; !ok || err != nil {
		t.Fatalf("ed25519 signature: %v", err)
	}
}

// rsa512PEM builds a throwaway 512-bit RSA key (too short on purpose). crypto/rsa no longer
// generates keys that short, so it is assembled from two random 256-bit primes.
func rsa512PEM(t *testing.T) []byte {
	t.Helper()
	for {
		p, err := rand.Prime(rand.Reader, 256)
		if err != nil {
			t.Fatal(err)
		}
		q, err := rand.Prime(rand.Reader, 256)
		if err != nil {
			t.Fatal(err)
		}
		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		d := new(big.Int).ModInverse(big.NewInt(65537), phi)
		if p.Cmp(q) == 0 || n.BitLen() != 512 || d == nil {
			continue
		}
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}, D: d, Primes: []*big.Int{p, q}}
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	}
}
