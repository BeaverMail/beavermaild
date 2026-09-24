// Recommended DNS records endpoint: real DKIM value, marked placeholders, hidden inactive rows, 401/403/404.
package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
)

type dnsRec struct {
	Type        string `json:"type"`
	Host        string `json:"host"`
	Value       string `json:"value"`
	Placeholder bool   `json:"placeholder"`
	Note        string `json:"note"`
}

func TestDomainDNSRecommended(t *testing.T) {
	t.Parallel()
	srv, dir := newTestAPI(t)
	dir.SetDataDir(t.TempDir())
	ctx := context.Background()
	dom, err := dir.CreateDomainWithOpts(ctx, directory.DefaultTenantID, "hosted.test", directory.DomainCreateOpts{DKIMEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	token := login(t, srv, "admin@api.test", "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/domains/hosted.test/dns-recommended", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("dns %d %s", res.Code, res.Body.String())
	}
	var out struct {
		Records []dnsRec `json:"records"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	find := func(typ, host string) dnsRec {
		t.Helper()
		for _, r := range out.Records {
			if r.Type == typ && r.Host == host {
				return r
			}
		}
		t.Fatalf("record %s %s missing in %+v", typ, host, out.Records)
		return dnsRec{}
	}

	// MX without mail hostname: value invented, so it must be flagged.
	mx := find("MX", "hosted.test")
	if !mx.Placeholder || mx.Note == "" {
		t.Fatalf("mx not marked placeholder: %+v", mx)
	}

	// DKIM: real selector and real key from the store, not a placeholder.
	dkimName, dkimVal, err := dir.DKIMDNSRecord(dom)
	if err != nil || dkimName == "" || dkimVal == "" {
		t.Fatalf("dkim dns name=%q val=%q err=%v", dkimName, dkimVal, err)
	}
	if dkimName != "beaver._domainkey.hosted.test" {
		t.Fatalf("dkim name %q", dkimName)
	}
	dkim := find("TXT", dkimName)
	if dkim.Placeholder || dkim.Value != dkimVal {
		t.Fatalf("dkim record not the real key: %+v", dkim)
	}

	// DMARC / MTA-STS / TLS-RPT are inactive: placeholder-only rows must not be returned.
	for _, host := range []string{"_dmarc.hosted.test", "_mta-sts.hosted.test", "_smtp._tls.hosted.test"} {
		for _, r := range out.Records {
			if r.Host == host {
				t.Fatalf("%s must be hidden while placeholder-only: %+v", host, r)
			}
		}
	}

	// DKIM not enabled: no key generated, so no _domainkey row at all (not even a placeholder).
	if _, err := dir.CreateDomainWithOpts(ctx, directory.DefaultTenantID, "nodkim.test", directory.DomainCreateOpts{}); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/domains/nodkim.test/dns-recommended", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("nodkim %d %s", res.Code, res.Body.String())
	}
	out.Records = nil
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, r := range out.Records {
		if strings.Contains(r.Host, "_domainkey") {
			t.Fatalf("dkim row must be hidden while no key is generated: %+v", r)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/domains/unknown.test/dns-recommended", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("unknown domain %d %s", res.Code, res.Body.String())
	}

	// DKIM read failure (key was generated but is unreadable now): the note must not
	// claim DKIM is disabled.
	dir.SetDataDir(t.TempDir())
	req = httptest.NewRequest(http.MethodGet, "/api/v1/domains/hosted.test/dns-recommended", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("dkim read fail %d %s", res.Code, res.Body.String())
	}
	out.Records = nil
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	dkim = find("TXT", dkimName)
	if !dkim.Placeholder || !strings.Contains(dkim.Note, "could not be read") ||
		strings.Contains(dkim.Note, "enable DKIM") {
		t.Fatalf("dkim read-failure note misleading: %+v", dkim)
	}
}

func TestDomainDNSRecommendedAuth(t *testing.T) {
	t.Parallel()
	srv, dir := newTestAPI(t)
	dir.SetDataDir(t.TempDir())
	ctx := context.Background()
	if _, err := dir.CreateDomainWithOpts(ctx, directory.DefaultTenantID, "hosted.test", directory.DomainCreateOpts{DKIMEnabled: true}); err != nil {
		t.Fatal(err)
	}
	get := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/domains/hosted.test/dns-recommended", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, req)
		return res
	}

	// 401: no credentials at all.
	if res := get(""); res.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: want 401 got %d %s", res.Code, res.Body.String())
	}

	// 403: plain user of a different domain (same tenant).
	dom, _, err := dir.EnsureDomain(ctx, directory.DefaultTenantID, "api.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAccount(ctx, dom.ID, "user", "secret"); err != nil {
		t.Fatal(err)
	}
	if res := get(login(t, srv, "user@api.test", "secret")); res.Code != http.StatusForbidden {
		t.Fatalf("user other domain: want 403 got %d %s", res.Code, res.Body.String())
	}
}
