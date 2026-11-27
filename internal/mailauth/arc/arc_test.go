// Tests exercise RFC 8617 chain structure, signatures, DNS, and limits.
package arc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
	testKeyErr  error
)

// generatedKey returns one generated RSA key shared by deterministic assertions.
func generatedKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		testKey, testKeyErr = rsa.GenerateKey(rand.Reader, 1024)
	})
	if testKeyErr != nil {
		t.Fatal(testKeyErr)
	}
	return testKey
}

// TestVerifyNone checks the normalized result for a message without ARC fields.
func TestVerifyNone(t *testing.T) {
	result, _ := Verify(context.Background(), strings.NewReader("From: a@example.test\r\n\r\nbody\r\n"), func(context.Context, string) ([]string, error) {
		t.Fatal("unexpected DNS lookup")
		return nil, nil
	})
	if result != ResultNone {
		t.Fatalf("result = %q, want none", result)
	}
}

// TestVerifyCanonicalizations checks simple and relaxed AMS body/header handling.
func TestVerifyCanonicalizations(t *testing.T) {
	for _, canonical := range []string{"simple/simple", "relaxed/relaxed"} {
		t.Run(canonical, func(t *testing.T) {
			key := generatedKey(t)
			raw := buildChain(t, key, canonical, 1)
			if result, _ := Verify(context.Background(), bytes.NewReader(raw), keyLookup(t, key)); result != ResultPass {
				t.Fatalf("result = %q, want pass", result)
			}
		})
	}
}

// TestVerifyTwoSetChain checks contiguous cv transitions and every ARC seal.
func TestVerifyTwoSetChain(t *testing.T) {
	key := generatedKey(t)
	raw := buildChain(t, key, "relaxed/relaxed", 2)
	if result, _ := Verify(context.Background(), bytes.NewReader(raw), keyLookup(t, key)); result != ResultPass {
		t.Fatalf("result = %q, want pass", result)
	}
}

// TestVerifyTamperedBody checks that an AMS body mismatch is a failure.
func TestVerifyTamperedBody(t *testing.T) {
	key := generatedKey(t)
	raw := buildChain(t, key, "relaxed/relaxed", 1)
	raw = bytes.Replace(raw, []byte("Body \t value"), []byte("changed"), 1)
	if result, _ := Verify(context.Background(), bytes.NewReader(raw), keyLookup(t, key)); result != ResultFail {
		t.Fatalf("result = %q, want fail", result)
	}
}

// TestVerifyMalformedChain checks gaps and invalid cv transitions.
func TestVerifyMalformedChain(t *testing.T) {
	key := generatedKey(t)
	valid := buildChain(t, key, "relaxed/relaxed", 1)
	tests := map[string][]byte{
		"gap":        bytes.ReplaceAll(valid, []byte("i=1"), []byte("i=2")),
		"bad cv":     bytes.Replace(valid, []byte("cv=none"), []byte("cv=pass"), 1),
		"seal h tag": bytes.Replace(valid, []byte("; cv=none;"), []byte("; cv=none; h=from;"), 1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if result, _ := Verify(context.Background(), bytes.NewReader(raw), keyLookup(t, key)); result != ResultFail {
				t.Fatalf("result = %q, want fail", result)
			}
		})
	}
}

// TestVerifyAdvertisedFailure checks the latest cv=fail short-circuit.
func TestVerifyAdvertisedFailure(t *testing.T) {
	key := generatedKey(t)
	raw := buildChain(t, key, "relaxed/relaxed", 1)
	raw = bytes.Replace(raw, []byte("cv=none"), []byte("cv=fail"), 1)
	if result, _ := Verify(context.Background(), bytes.NewReader(raw), keyLookup(t, key)); result != ResultFail {
		t.Fatalf("result = %q, want fail", result)
	}
}

// RFC 8617 5.2.1: every error, a DNS one included, is a permanent fail (it was temperror).
func TestVerifyDNSError(t *testing.T) {
	key := generatedKey(t)
	raw := buildChain(t, key, "simple/simple", 1)
	lookup := func(context.Context, string) ([]string, error) {
		return nil, errors.New("resolver unavailable")
	}
	if result, _ := Verify(context.Background(), bytes.NewReader(raw), lookup); result != ResultFail {
		t.Fatalf("result = %q, want fail", result)
	}
}

// TestVerifyStrictLimits: a large message without ARC fields is none; the body is only hashed as a
// stream, never held.
func TestVerifyStrictLimits(t *testing.T) {
	raw := append([]byte("From: a@example.test\r\n\r\n"), bytes.Repeat([]byte("x"), 32<<20)...)
	if result, _ := Verify(context.Background(), bytes.NewReader(raw), func(context.Context, string) ([]string, error) {
		return nil, nil
	}); result != ResultNone {
		t.Fatalf("result = %q, want none (no ARC field)", result)
	}
}

// keyLookup returns an injected DNS resolver for the generated public key.
func keyLookup(t *testing.T, key *rsa.PrivateKey) LookupTXT {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	return func(_ context.Context, name string) ([]string, error) {
		if name != "arc._domainkey.example.test" {
			t.Fatalf("lookup name = %q", name)
		}
		return []string{record}, nil
	}
}

// buildChain constructs and signs a complete one-domain ARC chain.
func buildChain(t *testing.T, key *rsa.PrivateKey, canonical string, count int) []byte {
	t.Helper()
	return buildChainDomain(t, key, canonical, count, "example.test")
}

// buildChainDomain is buildChain with every signature under domain.
func buildChainDomain(t *testing.T, key *rsa.PrivateKey, canonical string, count int, domain string) []byte {
	t.Helper()
	body := []byte("Body \t value \r\n\r\n")
	headers := []header{
		{name: "from", raw: "From: Sender <sender@example.test>"},
		{name: "subject", raw: "Subject:\t ARC   test "},
	}
	sets := make([]set, 0, count)
	for i := 1; i <= count; i++ {
		cv := "pass"
		if i == 1 {
			cv = "none"
		}
		aar := header{
			name: "arc-authentication-results",
			raw:  fmt.Sprintf("ARC-Authentication-Results: i=%d; mx.example.test; dkim=pass", i),
		}
		bodyMode := strings.Split(canonical, "/")[1]
		bh := bodyDigestOf(body, bodyMode).sum
		ams := header{
			name: "arc-message-signature",
			raw: fmt.Sprintf(
				"ARC-Message-Signature: i=%d; a=rsa-sha256; c=%s; d=%s; s=arc;\r\n\th=from:subject; bh=%s; b=",
				i, canonical, domain, base64.StdEncoding.EncodeToString(bh[:])),
		}
		var amsInput bytes.Buffer
		headerMode := strings.Split(canonical, "/")[0]
		from, _ := selectHeader(headers, "from", 0)
		subject, _ := selectHeader(headers, "subject", 0)
		amsInput.WriteString(canonicalizeHeader(from, headerMode))
		amsInput.WriteString(canonicalizeHeader(subject, headerMode))
		amsInput.WriteString(canonicalizeSignature(ams, headerMode))
		ams.raw += sign(t, key, amsInput.Bytes())
		parsedAMS, err := parseSignature(ams, false)
		if err != nil {
			t.Fatal(err)
		}
		seal := header{
			name: "arc-seal",
			raw: fmt.Sprintf(
				"ARC-Seal: i=%d; a=rsa-sha256; d=%s; s=arc; cv=%s; b=",
				i, domain, cv),
		}
		sets = append(sets, set{aar: aar, ams: parsedAMS, as: signature{header: seal}})
		var sealInput bytes.Buffer
		for n, current := range sets {
			sealInput.WriteString(canonicalizeHeader(current.aar, "relaxed"))
			sealInput.WriteString(canonicalizeHeader(current.ams.header, "relaxed"))
			if n < len(sets)-1 {
				sealInput.WriteString(canonicalizeHeader(current.as.header, "relaxed"))
			} else {
				sealInput.WriteString(canonicalizeSignature(current.as.header, "relaxed"))
			}
		}
		seal.raw += sign(t, key, sealInput.Bytes())
		parsedSeal, err := parseSignature(seal, true)
		if err != nil {
			t.Fatal(err)
		}
		sets[len(sets)-1].as = parsedSeal
		headers = append(headers, aar, ams, seal)
	}
	var raw bytes.Buffer
	for _, h := range headers {
		raw.WriteString(h.raw)
		raw.WriteString("\r\n")
	}
	raw.WriteString("\r\n")
	raw.Write(body)
	return raw.Bytes()
}

// sign creates a PKCS#1 v1.5 SHA-256 signature for a test header input.
func sign(t *testing.T, key *rsa.PrivateKey, input []byte) string {
	t.Helper()
	digest := sha256.Sum256(input)
	value, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(value)
}

// bodyDigestOf canonicalizes and hashes a whole body, as readMessage does while streaming.
func bodyDigestOf(body []byte, mode string) bodyDigest {
	c := newBodyCanon(mode == "relaxed")
	_, _ = c.Write(body)
	return c.digest()
}

// bodyOf is the message body field for body.
func bodyOf(body string) map[string]bodyDigest {
	return map[string]bodyDigest{"simple": bodyDigestOf([]byte(body), "simple"), "relaxed": bodyDigestOf([]byte(body), "relaxed")}
}

// The body is hashed as it streams: a 32 MB message is never held in memory.
func TestReadMessageStreamsBody(t *testing.T) {
	body := bytes.Repeat([]byte("lorem ipsum  dolor\r\n"), 32<<20/20)
	r := io.MultiReader(strings.NewReader("From: a@example.test\r\n\r\n"), bytes.NewReader(body))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	msg, err := readMessage(r)
	runtime.ReadMemStats(&after)
	if err != nil || len(msg.headers) != 1 {
		t.Fatal(err)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 4<<20 {
		t.Fatalf("reading a 32 MB body allocated %d MB", grown>>20)
	}
	if want := bodyDigestOf(body, "relaxed"); msg.body["relaxed"] != want {
		t.Fatal("streamed digest differs from the whole-body one")
	}
}
