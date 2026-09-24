// Recommended DNS records endpoint: real DKIM value, marked placeholders, 404.
package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	// DMARC / MTA-STS / TLS-RPT: values contain unconfigurable bits, so flagged with a note.
	for _, host := range []string{"_dmarc.hosted.test", "_mta-sts.hosted.test", "_smtp._tls.hosted.test"} {
		r := find("TXT", host)
		if !r.Placeholder || r.Note == "" {
			t.Fatalf("%s not marked placeholder: %+v", host, r)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/domains/unknown.test/dns-recommended", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("unknown domain %d %s", res.Code, res.Body.String())
	}
}
