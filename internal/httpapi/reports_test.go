// Domain report endpoint: aggregates from parsed reports only, unparsed listed
// honestly, 401/403/404.
package httpapi_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/httpapi"
)

// dmarcFixture is a realistic DMARC aggregate body (RFC 7489 Appendix C) for the
// test domain: 3 records covering aligned pass, spoofing and a foreign header_from.
const dmarcFixture = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>12345678901234567890</report_id>
    <date_range>
      <begin>1609459200</begin>
      <end>1609545599</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>api.test</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.7</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>api.test</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>api.test</domain>
        <selector>beaver</selector>
        <result>pass</result>
      </dkim>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.4</source_ip>
      <count>7</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>api.test</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>spoof.example</domain>
        <scope>mfrom</scope>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>192.0.2.99</source_ip>
      <count>2</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>other.example</header_from>
    </identifiers>
  </record>
</feedback>`

// tlsFixture is a realistic TLS-RPT body (RFC 8460 Section 2.1/2.2).
const tlsFixture = `{
  "organization-name": "Beaver Mail",
  "date-range": {
    "start-datetime": "2026-02-01T00:00:00Z",
    "end-datetime": "2026-02-01T23:59:59Z"
  },
  "contact-info": "mailto:tls-reports@api.test",
  "report-id": "beaver-2026-02-01",
  "policies": [
    {
      "policy": {
        "policy-type": "sts",
        "policy-string": ["version: STSv1", "mode: testing", "mx: mail.api.test"],
        "policy-domain": "api.test"
      },
      "summary": {
        "total-successful-session-count": 42,
        "total-failure-session-count": 3
      },
      "failure-details": [
        {
          "result-type": "starttls-not-supported",
          "sending-mta-ip": "203.0.113.9",
          "receiving-mx-hostname": "mail.api.test",
          "receiving-mx-ip": "203.0.113.10",
          "failed-session-count": 3
        }
      ]
    }
  ]
}`

// fixtureGzipB64 returns the payload gzip-compressed and base64-encoded, as real
// report senders put it on the wire.
func fixtureGzipB64(t *testing.T, payload string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// fixtureMessage wraps a base64 gzip attachment in a realistic multipart message.
func fixtureMessage(contentType, filename, attachment string) string {
	return fmt.Sprintf(`From: Google DMARC <noreply-dmarc-support@google.com>
To: dmarc-reports@api.test
Subject: Report domain: api.test Submitter: google.com Report-ID: 12345678901234567890
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="000000000000abc"

--000000000000abc
Content-Type: text/plain; charset="utf-8"

This is an aggregate report, see attachment.
--000000000000abc
Content-Type: %s; name="%s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="%s"

%s
--000000000000abc--
`, contentType, filename, filename, attachment)
}

type reportsOut struct {
	Domain  string `json:"domain"`
	Reports []struct {
		directory.ReportMeta
		Parsed   bool     `json:"parsed"`
		Problems []string `json:"problems"`
	} `json:"reports"`
	DMARC *struct {
		Reports   int `json:"reports"`
		Messages  int `json:"messages"`
		DKIMPass  int `json:"dkim_pass"`
		SPFPass   int `json:"spf_pass"`
		DMARCPass int `json:"dmarc_pass"`
		DMARCFail int `json:"dmarc_fail"`
		Spoofing  struct {
			Messages  int      `json:"messages"`
			SourceIPs []string `json:"source_ips"`
		} `json:"spoofing"`
	} `json:"dmarc"`
	TLS *struct {
		Reports            int `json:"reports"`
		SuccessfulSessions int `json:"successful_sessions"`
		FailedSessions     int `json:"failed_sessions"`
		MXFailures         []struct {
			MX             string   `json:"mx"`
			FailedSessions int      `json:"failed_sessions"`
			ResultTypes    []string `json:"result_types"`
		} `json:"mx_failures"`
	} `json:"tls"`
}

func getReports(t *testing.T, srv *httpapi.Server, token, domain string) (int, *reportsOut, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/domains/"+domain+"/reports", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		return res.Code, nil, res.Body.String()
	}
	var out reportsOut
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", res.Body.String(), err)
	}
	return res.Code, &out, res.Body.String()
}

func TestDomainReportsAggregates(t *testing.T) {
	t.Parallel()
	srv, dir := newTestAPI(t)
	dataDir := t.TempDir()
	dir.SetDataDir(dataDir)
	ctx := context.Background()
	dom, err := dir.LookupDomain(ctx, "api.test")
	if err != nil {
		t.Fatal(err)
	}
	token := login(t, srv, "admin@api.test", "secret")

	dmarcRaw := []byte(fixtureMessage("application/gzip",
		"google.com!api.test!1609459200!1609545599!12345678901234567890.xml.gz",
		fixtureGzipB64(t, dmarcFixture)))
	tlsRaw := []byte(fixtureMessage("application/gzip",
		"api.test!beaver-2026-02-01.json.gz", fixtureGzipB64(t, tlsFixture)))
	corruptRaw := []byte(fixtureMessage("application/gzip",
		"google.com!api.test!1!2!bad.xml.gz", fixtureGzipB64(t, "<feedback><report_metadata>")))
	if _, err := directory.SaveDomainReport(dataDir, dom.ID, "dmarc", "noreply@google.com", "dmarc-reports@api.test", dmarcRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.SaveDomainReport(dataDir, dom.ID, "tls", "tls-reports@google.com", "tls-reports@api.test", tlsRaw); err != nil {
		t.Fatal(err)
	}
	corruptPath, err := directory.SaveDomainReport(dataDir, dom.ID, "dmarc", "bad@sender.example", "dmarc-reports@api.test", corruptRaw)
	if err != nil {
		t.Fatal(err)
	}

	code, out, _ := getReports(t, srv, token, "api.test")
	if code != http.StatusOK || out.Domain != "api.test" {
		t.Fatalf("code %d domain %q", code, out.Domain)
	}
	if len(out.Reports) != 3 {
		t.Fatalf("reports = %d, want 3: %+v", len(out.Reports), out.Reports)
	}
	find := func(kind string, parsed bool) *struct {
		directory.ReportMeta
		Parsed   bool     `json:"parsed"`
		Problems []string `json:"problems"`
	} {
		t.Helper()
		for i := range out.Reports {
			if out.Reports[i].Kind == kind && out.Reports[i].Parsed == parsed {
				return &out.Reports[i]
			}
		}
		t.Fatalf("report kind=%s parsed=%v missing in %+v", kind, parsed, out.Reports)
		return nil
	}
	dmarcItem := find("dmarc", true)
	if dmarcItem.From != "noreply@google.com" || dmarcItem.File == "" || dmarcItem.ReceivedAt == "" {
		t.Fatalf("dmarc meta = %+v", dmarcItem.ReportMeta)
	}
	if len(dmarcItem.Problems) != 0 {
		t.Fatalf("dmarc problems = %v", dmarcItem.Problems)
	}
	tlsItem := find("tls", true)
	if tlsItem.From != "tls-reports@google.com" {
		t.Fatalf("tls meta = %+v", tlsItem.ReportMeta)
	}

	// Corrupt report: listed with its problem, never counted, store untouched.
	bad := find("dmarc", false)
	if len(bad.Problems) == 0 {
		t.Fatalf("corrupt report without problems: %+v", bad)
	}
	if raw, err := os.ReadFile(corruptPath); err != nil || !bytes.Equal(raw, corruptRaw) {
		t.Fatalf("store modified by GET: err=%v equal=%v", err, bytes.Equal(raw, corruptRaw))
	}

	// Aggregates only from the one parsed DMARC report (12 messages over 3 records).
	if out.DMARC == nil {
		t.Fatal("dmarc aggregates missing")
	}
	d := out.DMARC
	if d.Reports != 1 || d.Messages != 12 {
		t.Fatalf("dmarc totals = %+v", d)
	}
	if d.DKIMPass != 3 || d.SPFPass != 0 || d.DMARCPass != 3 || d.DMARCFail != 9 {
		t.Fatalf("dmarc outcomes = %+v", d)
	}
	// Spoofing: only the aligned header_from with both SPF and DKIM failing.
	if d.Spoofing.Messages != 7 || len(d.Spoofing.SourceIPs) != 1 || d.Spoofing.SourceIPs[0] != "198.51.100.4" {
		t.Fatalf("spoofing = %+v", d.Spoofing)
	}

	if out.TLS == nil {
		t.Fatal("tls aggregates missing")
	}
	tr := out.TLS
	if tr.Reports != 1 || tr.SuccessfulSessions != 42 || tr.FailedSessions != 3 {
		t.Fatalf("tls totals = %+v", tr)
	}
	if len(tr.MXFailures) != 1 {
		t.Fatalf("tls mx failures = %+v", tr.MXFailures)
	}
	mx := tr.MXFailures[0]
	if mx.MX != "mail.api.test" || mx.FailedSessions != 3 ||
		len(mx.ResultTypes) != 1 || mx.ResultTypes[0] != "starttls-not-supported" {
		t.Fatalf("tls mx failure = %+v", mx)
	}

	if code, _, _ := getReports(t, srv, token, "unknown.test"); code != http.StatusNotFound {
		t.Fatalf("unknown domain: want 404 got %d", code)
	}
}

func TestDomainReportsAuth(t *testing.T) {
	t.Parallel()
	srv, dir := newTestAPI(t)
	dir.SetDataDir(t.TempDir())
	ctx := context.Background()
	if _, err := dir.CreateDomainWithOpts(ctx, directory.DefaultTenantID, "hosted.test", directory.DomainCreateOpts{}); err != nil {
		t.Fatal(err)
	}

	// 401: no credentials at all.
	if code, _, _ := getReports(t, srv, "", "hosted.test"); code != http.StatusUnauthorized {
		t.Fatalf("no auth: want 401 got %d", code)
	}

	// 403: plain user of a different domain (same tenant).
	dom, _, err := dir.EnsureDomain(ctx, directory.DefaultTenantID, "api.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAccount(ctx, dom.ID, "user", "secret"); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := getReports(t, srv, login(t, srv, "user@api.test", "secret"), "hosted.test"); code != http.StatusForbidden {
		t.Fatalf("user other domain: want 403 got %d", code)
	}

	// No reports in store: empty list, no aggregates keys at all (never zero-filled).
	code, out, raw := getReports(t, srv, login(t, srv, "admin@api.test", "secret"), "hosted.test")
	if code != http.StatusOK || len(out.Reports) != 0 {
		t.Fatalf("empty store: code %d reports %+v", code, out.Reports)
	}
	// Key absence on the raw wire body: "dmarc":null would decode as nil too.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		t.Fatalf("decode keys %s: %v", raw, err)
	}
	for _, key := range []string{"dmarc", "tls"} {
		if _, ok := keys[key]; ok {
			t.Fatalf("aggregates key %q present in empty-store response: %s", key, raw)
		}
	}
}
