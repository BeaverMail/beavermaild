// SPDX-License-Identifier: Apache-2.0

package license

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testProduct(t *testing.T) (Product, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return Product{Plugin: "widget", PublicKey: pub, Released: "2026-11-01", BuyURL: "https://example.com/buy"}, priv
}

func sign(t *testing.T, priv ed25519.PrivateKey, lic License) []byte {
	t.Helper()
	b, err := Sign(priv, lic)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerify(t *testing.T) {
	p, priv := testProduct(t)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	dom := License{Plugin: "widget", Model: ModelOneshot, Licensee: "Example Ltd", Domains: []string{"example.com"}}
	inst := License{Plugin: "widget", Model: ModelPerpetual, Licensee: "Example Ltd", InstallID: "abc", UpdatesUntil: "2027-11-11"}

	cases := []struct {
		name    string
		data    []byte
		install string
		wantErr string
	}{
		{"oneshot domains", sign(t, priv, dom), "", ""},
		{"perpetual install", sign(t, priv, inst), "abc", ""},
		{"other install", sign(t, priv, inst), "xyz", "installation abc"},
		{"no install id", sign(t, priv, inst), "", "this is unknown"},
		{"wrong key", sign(t, otherPriv, dom), "", "bad license signature"},
		{"wrong plugin", sign(t, priv, License{Plugin: "other", Model: ModelOneshot, Domains: []string{"example.com"}}), "", `for plugin "other"`},
		{"no scope", sign(t, priv, License{Plugin: "widget", Model: ModelOneshot}), "", "either domains or an install id"},
		{"two scopes", sign(t, priv, License{Plugin: "widget", Model: ModelOneshot, Domains: []string{"example.com"}, InstallID: "abc"}), "abc", "either domains"},
		{"unknown model", sign(t, priv, License{Plugin: "widget", Model: "subscription", Domains: []string{"example.com"}}), "", "unknown license model"},
		{"perpetual without date", sign(t, priv, License{Plugin: "widget", Model: ModelPerpetual, Domains: []string{"example.com"}}), "", "updates_until"},
		{"updates ended", sign(t, priv, License{Plugin: "widget", Model: ModelPerpetual, Domains: []string{"example.com"}, UpdatesUntil: "2026-10-31"}), "", "does not cover this version"},
		{"garbage", []byte("not json"), "", "malformed license file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.Verify(tc.data, tc.install)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Verify err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyTamperedPayload(t *testing.T) {
	p, priv := testProduct(t)
	data := sign(t, priv, License{Plugin: "widget", Model: ModelOneshot, Domains: []string{"example.com"}})
	data = bytes.Replace(data, []byte("example.com"), []byte("example.org"), 1)
	if _, err := p.Verify(data, ""); err == nil || !strings.Contains(err.Error(), "bad license signature") {
		t.Fatalf("tampered payload accepted: %v", err)
	}
}

func TestReleasedOnLastDayIsCovered(t *testing.T) {
	p, priv := testProduct(t)
	data := sign(t, priv, License{Plugin: "widget", Model: ModelPerpetual, Domains: []string{"example.com"}, UpdatesUntil: p.Released})
	if _, err := p.Verify(data, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(sign(t, priv, License{Plugin: "widget", Model: ModelPerpetual, Domains: []string{"example.com"}, UpdatesUntil: "2026-10-31"}), ""); !errors.Is(err, ErrNotCovered) {
		t.Fatalf("err = %v, want ErrNotCovered", err)
	}
}

func TestLoadFrom(t *testing.T) {
	p, priv := testProduct(t)
	dir := t.TempDir()
	if _, err := p.LoadFrom(dir, ""); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing file: err = %v", err)
	}
	if _, err := p.LoadFrom("", ""); !errors.Is(err, ErrMissing) {
		t.Fatalf("no dir: err = %v", err)
	}
	data := sign(t, priv, License{Plugin: "widget", Model: ModelOneshot, Domains: []string{"example.com"}})
	if err := os.WriteFile(filepath.Join(dir, "widget.lic"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.LoadFrom(dir, ""); err != nil {
		t.Fatal(err)
	}
	if msg := p.Message(ErrMissing); !strings.Contains(msg, "widget.lic") || !strings.Contains(msg, "https://example.com/buy") {
		t.Fatalf("Message = %q", msg)
	}
}

func TestAllowsAccount(t *testing.T) {
	dom := License{Domains: []string{"example.com"}}
	for email, want := range map[string]bool{
		"alice@example.com":     true,
		"alice@EXAMPLE.com":     true,
		"alice@example.org":     false,
		"alice@sub.example.com": false,
		"no-at-sign":            false,
	} {
		if got := dom.AllowsAccount(email); got != want {
			t.Errorf("AllowsAccount(%q) = %v, want %v", email, got, want)
		}
	}
	if !(License{InstallID: "abc"}).AllowsAccount("alice@example.org") {
		t.Error("install-scoped license must allow any domain")
	}
}
