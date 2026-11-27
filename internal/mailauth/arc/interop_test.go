package arc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
)

// ARC signatures are DKIM signatures (RFC 8617 4.1.2, 5.2): the hashing path must verify what an
// independent DKIM implementation signs. X1: the signature field was hashed with a trailing CRLF
// (RFC 6376 3.7 says without), so no chain sealed elsewhere could verify; the old tests signed with
// the same code and never noticed. X2: relaxed empty body is the null input. X6: Ed25519.
func TestHashPathMatchesIndependentSigner(t *testing.T) {
	t.Parallel()
	rsaKey := generatedKey(t)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{
		"rsa._domainkey.example.test": "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der),
		"ed._domainkey.example.test":  "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(edKey.Public().(ed25519.PublicKey)),
	}
	lookup := func(_ context.Context, name string) ([]string, error) { return []string{records[name]}, nil }
	bodies := map[string]string{
		"text":  "Hello \t world  \r\n\r\n\r\n",
		"empty": "",
		// 8-bit text in a legacy charset: canonicalization works on octets.
		"latin1":                 "caf\xe9 \t cr\xe8me  \r\n \t \r\n\xff\r\n\r\n",
		"blank lines and spaces": "\r\n  \r\na\r\n\t\r\n\r\n",
		"no final line end":      "last line  ",
		"long line":              strings.Repeat("x y  ", 20000) + "\r\n",
	}
	for _, canon := range []dkim.Canonicalization{dkim.CanonicalizationSimple, dkim.CanonicalizationRelaxed} {
		for selector, signer := range map[string]crypto.Signer{"rsa": rsaKey, "ed": edKey} {
			for bodyName, body := range bodies {
				name := string(canon) + "/" + selector + "/" + bodyName
				t.Run(name, func(t *testing.T) {
					msg := "From: Sender <sender@example.test>\r\nSubject:  Hi \t there\r\nTo: rcpt@example.test\r\n\r\n" + body
					var out bytes.Buffer
					if err := dkim.Sign(&out, strings.NewReader(msg), &dkim.SignOptions{
						Domain: "example.test", Selector: selector, Signer: signer,
						HeaderCanonicalization: canon, BodyCanonicalization: canon,
						HeaderKeys: []string{"From", "Subject", "To", "Date"},
					}); err != nil {
						t.Fatal(err)
					}
					parsed, err := readMessage(bytes.NewReader(out.Bytes()))
					if err != nil {
						t.Fatal(err)
					}
					sig := parsed.headers[0] // dkim.Sign prepends its field
					if sig.name != "dkim-signature" {
						t.Fatalf("first field %q", sig.name)
					}
					value, _ := headerValue(sig)
					tags, err := parseTags(value)
					if err != nil {
						t.Fatal(err)
					}
					keys := &keyCache{lookup: lookup, seen: map[string]keyAnswer{}}
					if err := verifyMessageSignature(context.Background(), parsed, sig, tags, keys); err != nil {
						t.Fatalf("independent signature rejected: %v", err)
					}
				})
			}
		}
	}
}

// X9: an l= shorter than the body leaves appended text unsigned; such a signature fails.
func TestBodyLengthMustCoverBody(t *testing.T) {
	t.Parallel()
	key := generatedKey(t)
	raw := buildChain(t, key, "relaxed/relaxed", 1)
	appended := append(bytes.TrimSuffix(raw, []byte("\r\n")), []byte("\r\nAppended spam\r\n")...)
	if result, _ := Verify(context.Background(), bytes.NewReader(appended), keyLookup(t, key)); result != ResultFail {
		t.Fatalf("appended body: %q", result)
	}
	if err := verifyMessageSignature(context.Background(), message{body: bodyOf("abc\r\n")}, header{},
		map[string]string{"l": "1", "bh": "x"}, nil); err == nil {
		t.Fatal("l=1 over a longer body accepted")
	}
}

// X7, X5: one DNS query per key name for the whole chain; a pass reports the newest sealer.
func TestKeyCacheAndSealer(t *testing.T) {
	t.Parallel()
	key := generatedKey(t)
	raw := buildChain(t, key, "relaxed/relaxed", 3)
	lookups := 0
	inner := keyLookup(t, key)
	result, sealer := Verify(context.Background(), bytes.NewReader(raw), func(ctx context.Context, name string) ([]string, error) {
		lookups++
		return inner(ctx, name)
	})
	if result != ResultPass || sealer != "example.test" || lookups != 1 {
		t.Fatalf("result %q sealer %q lookups %d", result, sealer, lookups)
	}
}

// 32 MB appended to a chained message: the body is hashed as a stream and no longer matches, so
// the chain fails.
func TestOversizedWithChain(t *testing.T) {
	t.Parallel()
	key := generatedKey(t)
	raw := buildChain(t, key, "relaxed/relaxed", 1)
	raw = append(raw, bytes.Repeat([]byte("x"), 32<<20)...)
	if result, _ := Verify(context.Background(), bytes.NewReader(raw), keyLookup(t, key)); result != ResultFail {
		t.Fatalf("result %q, want fail", result)
	}
}

// F1-F4 (RFC 8617 audit, found running an external ARC test suite locally): tag-list syntax per
// RFC 6376 3.2.
func TestTagListSyntax(t *testing.T) {
	t.Parallel()
	seal := func(v string) header { return header{name: "arc-seal", raw: "ARC-Seal: " + v} }
	const base = "i=1; a=rsa-sha256; d=example.test; s=arc; cv=none; b=AAAA"
	for name, tc := range map[string]struct {
		value string
		ok    bool
	}{
		"valid":                           {base, true},
		"trailing semicolon":              {base + ";", true},
		"F1 tag names are case-sensitive": {"i=1; A=rsa-sha256; d=example.test; s=arc; cv=none; b=AAAA", false}, // no a=
		"F2 empty tag-spec":               {"i=1; a=rsa-sha256;; d=example.test; s=arc; cv=none; b=AAAA", false},
		"F3 unknown tag ignored":          {base + "; x-future=1", true},
		"h= fails a seal":                 {base + "; h=from", false},
	} {
		if _, err := parseSignature(seal(tc.value), true); (err == nil) != tc.ok {
			t.Errorf("%s: err %v", name, err)
		}
	}
	// F4: c= present but empty is an error, not the simple/simple default.
	err := verifyMessageSignature(context.Background(), message{body: bodyOf("x\r\n")}, header{}, map[string]string{"c": "", "bh": "x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "empty c=") {
		t.Fatalf("empty c=: %v", err)
	}
}

// Review C1: a sealer d= in U-labels (RFC 8617 4.1.4) comes back as an A-label, the form trust
// lists hold; it never matched before.
func TestARCSealerALabel(t *testing.T) {
	t.Parallel()
	key := generatedKey(t)
	raw := buildChainDomain(t, key, "relaxed/relaxed", 1, "münchen.example")
	inner := keyLookup(t, key)
	result, sealer := Verify(context.Background(), bytes.NewReader(raw), func(ctx context.Context, name string) ([]string, error) {
		return inner(ctx, "arc._domainkey.example.test")
	})
	if result != ResultPass || sealer != "xn--mnchen-3ya.example" {
		t.Fatalf("result %q sealer %q", result, sealer)
	}
}

// Relaxed header canonicalization works on octets too: an 8-bit Subject signed elsewhere verifies.
func TestHeaderCanonicalizationOctets(t *testing.T) {
	t.Parallel()
	key := generatedKey(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	lookup := func(context.Context, string) ([]string, error) { return []string{record}, nil }
	msg := "From: sender@example.test\r\nSubject: caf\xe9  \t cr\xe8me\r\n\r\nbody\r\n"
	var out bytes.Buffer
	if err := dkim.Sign(&out, strings.NewReader(msg), &dkim.SignOptions{
		Domain: "example.test", Selector: "rsa", Signer: key,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed, BodyCanonicalization: dkim.CanonicalizationRelaxed,
		HeaderKeys: []string{"From", "Subject"},
	}); err != nil {
		t.Fatal(err)
	}
	parsed, err := readMessage(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	value, _ := headerValue(parsed.headers[0])
	tags, err := parseTags(value)
	if err != nil {
		t.Fatal(err)
	}
	keys := &keyCache{lookup: lookup, seen: map[string]keyAnswer{}}
	if err := verifyMessageSignature(context.Background(), parsed, parsed.headers[0], tags, keys); err != nil {
		t.Fatalf("8-bit Subject: %v", err)
	}
}
