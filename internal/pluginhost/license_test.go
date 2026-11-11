package pluginhost

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/plugin"
	"github.com/BeaverMail/beavermaild/plugin/license"
)

func TestLicenseStatus(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	e := Entry{Name: "widget", License: plugin.LicensePaid, LicenseKey: base64.StdEncoding.EncodeToString(pub), Released: "2026-11-01"}
	dir := t.TempDir()
	write := func(lic license.License) {
		b, err := license.Sign(priv, lic)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "widget.lic"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if got := LicenseStatus(Entry{Name: "free", License: plugin.LicenseFree}, dir, ""); got != "free" {
		t.Errorf("free plugin: %q", got)
	}
	if got := LicenseStatus(Entry{Name: "other"}, dir, ""); got != "-" {
		t.Errorf("undeclared: %q", got)
	}
	if got := LicenseStatus(e, dir, ""); !strings.HasPrefix(got, "missing") {
		t.Errorf("no file: %q", got)
	}
	write(license.License{Plugin: "widget", Model: license.ModelPerpetual, InstallID: "abc", UpdatesUntil: "2027-11-11"})
	if got := LicenseStatus(e, dir, "abc"); got != "valid, updates until 2027-11-11" {
		t.Errorf("valid perpetual: %q", got)
	}
	if got := LicenseStatus(e, dir, "xyz"); !strings.HasPrefix(got, "invalid") {
		t.Errorf("other install: %q", got)
	}
	write(license.License{Plugin: "widget", Model: license.ModelPerpetual, InstallID: "abc", UpdatesUntil: "2026-10-31"})
	if got := LicenseStatus(e, dir, "abc"); !strings.HasPrefix(got, "expired") {
		t.Errorf("updates ended: %q", got)
	}
	write(license.License{Plugin: "widget", Model: license.ModelOneshot, Domains: []string{"example.com"}})
	if got := LicenseStatus(e, dir, ""); got != "valid domains=example.com" {
		t.Errorf("oneshot domains: %q", got)
	}
}
