package directory

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// dmarcXML is a realistic DMARC aggregate report body (RFC 7489 Appendix C).
const dmarcXML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <extra_contact_info>https://support.google.com/a/answer/2466580</extra_contact_info>
    <report_id>12345678901234567890</report_id>
    <date_range>
      <begin>1609459200</begin>
      <end>1609545599</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>beaver.test</domain>
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
        <reason>
          <type>forwarded</type>
          <comment>message was forwarded</comment>
        </reason>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>beaver.test</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>beaver.test</domain>
        <selector>beaver</selector>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>beaver.test</domain>
        <scope>mfrom</scope>
        <result>fail</result>
      </spf>
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
      <header_from>beaver.test</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>spoof.example</domain>
        <scope>mfrom</scope>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>`

// tlsJSON is a realistic TLS-RPT report body (RFC 8460 Section 2.1/2.2).
const tlsJSON = `{
  "organization-name": "Beaver Mail",
  "date-range": {
    "start-datetime": "2026-02-01T00:00:00Z",
    "end-datetime": "2026-02-01T23:59:59Z"
  },
  "contact-info": "mailto:tls-reports@beaver.test",
  "report-id": "beaver-2026-02-01",
  "policies": [
    {
      "policy": {
        "policy-type": "sts",
        "policy-string": ["version: STSv1", "mode: testing", "mx: mail.beaver.test"],
        "policy-domain": "beaver.test"
      },
      "summary": {
        "total-successful-session-count": 42,
        "total-failure-session-count": 3
      },
      "failure-details": [
        {
          "result-type": "starttls-not-supported",
          "sending-mta-ip": "203.0.113.9",
          "receiving-mx-hostname": "mail.beaver.test",
          "receiving-mx-ip": "203.0.113.10",
          "failed-session-count": 3
        }
      ]
    }
  ]
}`

// gzipB64 returns the fixture payload gzip-compressed and base64-encoded, as real
// report senders put it on the wire.
func gzipB64(t *testing.T, payload string) string {
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

// parseLogger returns a logger that keeps its Warn output in a buffer.
func parseLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), &buf
}

// reportMessage wraps a base64 gzip attachment in a realistic multipart message.
func reportMessage(contentType, filename, attachment string) string {
	return fmt.Sprintf(`From: Google DMARC <noreply-dmarc-support@google.com>
To: dmarc-reports@beaver.test
Subject: Report domain: beaver.test Submitter: google.com Report-ID: 12345678901234567890
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

func TestParseDMARCAggregateGzipAttachment(t *testing.T) {
	raw := reportMessage("application/gzip",
		"google.com!beaver.test!1609459200!1609545599!1234567890.xml.gz",
		gzipB64(t, dmarcXML))
	log, buf := parseLogger()
	res := ParseReport(log, "dmarc", []byte(raw))
	if len(res.Problems) != 0 {
		t.Fatalf("unexpected problems: %v", res.Problems)
	}
	if buf.Len() != 0 {
		t.Fatalf("unexpected log output: %s", buf.String())
	}
	if res.Format != "xml" {
		t.Fatalf("format = %q, want xml", res.Format)
	}
	if res.DMARC == nil {
		t.Fatal("DMARC report not parsed")
	}
	if res.TLS != nil {
		t.Fatal("TLS report must stay nil for kind=dmarc")
	}
	md := res.DMARC.ReportMetadata
	if md.OrgName != "google.com" || md.ReportID != "12345678901234567890" {
		t.Fatalf("metadata = %+v", md)
	}
	if md.DateRange.Begin != "1609459200" || md.DateRange.End != "1609545599" {
		t.Fatalf("date range = %+v", md.DateRange)
	}
	pol := res.DMARC.PolicyPublished
	if pol.Domain != "beaver.test" || pol.P != "none" || pol.PCT != 100 {
		t.Fatalf("policy = %+v", pol)
	}
	recs := res.DMARC.Records
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	r0 := recs[0]
	if r0.Row.SourceIP != "203.0.113.7" || r0.Row.Count != 3 {
		t.Fatalf("row 0 = %+v", r0.Row)
	}
	if r0.Row.PolicyEvaluated.DKIM != "pass" || r0.Row.PolicyEvaluated.SPF != "fail" {
		t.Fatalf("policy_evaluated 0 = %+v", r0.Row.PolicyEvaluated)
	}
	if len(r0.Row.PolicyEvaluated.Reasons) != 1 || r0.Row.PolicyEvaluated.Reasons[0].Type != "forwarded" {
		t.Fatalf("reasons 0 = %+v", r0.Row.PolicyEvaluated.Reasons)
	}
	if len(r0.AuthResults.DKIM) != 1 || r0.AuthResults.DKIM[0].Domain != "beaver.test" ||
		r0.AuthResults.DKIM[0].Selector != "beaver" || r0.AuthResults.DKIM[0].Result != "pass" {
		t.Fatalf("dkim auth 0 = %+v", r0.AuthResults.DKIM)
	}
	r1 := recs[1]
	if r1.Row.PolicyEvaluated.Disposition != "reject" || r1.Row.Count != 7 {
		t.Fatalf("row 1 = %+v", r1.Row)
	}
	if r1.Identifiers.HeaderFrom != "beaver.test" {
		t.Fatalf("identifiers 1 = %+v", r1.Identifiers)
	}
	if len(r1.AuthResults.SPF) != 1 || r1.AuthResults.SPF[0].Domain != "spoof.example" {
		t.Fatalf("spf auth 1 = %+v", r1.AuthResults.SPF)
	}
}

func TestParseTLSRPTGzipAttachment(t *testing.T) {
	// application/octet-stream + .json.gz name: format sniffed by magic bytes/name.
	raw := reportMessage("application/octet-stream",
		"beaver.test!beaver-2026-02-01.json.gz", gzipB64(t, tlsJSON))
	log, buf := parseLogger()
	res := ParseReport(log, "tls", []byte(raw))
	if len(res.Problems) != 0 {
		t.Fatalf("unexpected problems: %v", res.Problems)
	}
	if buf.Len() != 0 {
		t.Fatalf("unexpected log output: %s", buf.String())
	}
	if res.Format != "json" {
		t.Fatalf("format = %q, want json", res.Format)
	}
	if res.TLS == nil {
		t.Fatal("TLS report not parsed")
	}
	if res.DMARC != nil {
		t.Fatal("DMARC report must stay nil for kind=tls")
	}
	rep := res.TLS
	if rep.OrganizationName != "Beaver Mail" || rep.ReportID != "beaver-2026-02-01" {
		t.Fatalf("report = %+v", rep)
	}
	if rep.DateRange.StartDatetime != "2026-02-01T00:00:00Z" {
		t.Fatalf("date range = %+v", rep.DateRange)
	}
	if len(rep.Policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(rep.Policies))
	}
	p := rep.Policies[0]
	if p.Policy.PolicyType != "sts" || p.Policy.PolicyDomain != "beaver.test" ||
		len(p.Policy.PolicyString) != 3 {
		t.Fatalf("policy = %+v", p.Policy)
	}
	if p.Summary.TotalSuccessfulSessionCount != 42 || p.Summary.TotalFailureSessionCount != 3 {
		t.Fatalf("summary = %+v", p.Summary)
	}
	if len(p.FailureDetails) != 1 {
		t.Fatalf("failure details = %d, want 1", len(p.FailureDetails))
	}
	f := p.FailureDetails[0]
	if f.ResultType != "starttls-not-supported" || f.FailedSessionCount != 3 ||
		f.ReceivingMXHostname != "mail.beaver.test" {
		t.Fatalf("failure = %+v", f)
	}
}

func TestParseDMARCPlainXMLBody(t *testing.T) {
	raw := `From: reporter@example.net
To: dmarc-reports@beaver.test
Subject: DMARC aggregate report
MIME-Version: 1.0
Content-Type: application/xml; charset="utf-8"

` + dmarcXML
	log, buf := parseLogger()
	res := ParseReport(log, "dmarc", []byte(raw))
	if len(res.Problems) != 0 || res.DMARC == nil {
		t.Fatalf("problems = %v, dmarc = %v", res.Problems, res.DMARC)
	}
	if res.DMARC.ReportMetadata.ReportID != "12345678901234567890" || buf.Len() != 0 {
		t.Fatalf("report = %+v, log = %s", res.DMARC, buf.String())
	}
}

func TestParseCorruptReport(t *testing.T) {
	// (a) truncated XML inside a gzip attachment: parse error logged, nothing invented.
	broken := reportMessage("application/gzip", "broken.xml.gz",
		gzipB64(t, `<feedback><report_metadata><org_name>google.com</org_name>`))
	log, buf := parseLogger()
	res := ParseReport(log, "dmarc", []byte(broken))
	if len(res.Problems) == 0 {
		t.Fatal("corrupt XML must produce a problem")
	}
	if res.DMARC != nil {
		t.Fatalf("corrupt XML must not yield a report: %+v", res.DMARC)
	}
	if res.Format != "xml" {
		t.Fatalf("format = %q, want xml (payload identified, parse failed)", res.Format)
	}
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "report parse") {
		t.Fatalf("problem not logged at Warn: %q", buf.String())
	}

	// (b) not even a message: unknown format, problem logged.
	log2, buf2 := parseLogger()
	res2 := ParseReport(log2, "dmarc", []byte("\x00\x01 not a message"))
	if res2.Format != "unknown" || len(res2.Problems) == 0 || res2.DMARC != nil {
		t.Fatalf("res2 = %+v", res2)
	}
	if !strings.Contains(buf2.String(), "level=WARN") {
		t.Fatalf("problem not logged at Warn: %q", buf2.String())
	}

	// (c) store integrity: the raw report survives parsing untouched.
	dataDir := t.TempDir()
	rawPath, err := SaveDomainReport(dataDir, 7, "dmarc", "noreply@example.net",
		"dmarc-reports@beaver.test", []byte(broken))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, []byte(broken)) {
		t.Fatal("stored raw report differs from the ingested message")
	}
	res3 := ParseReport(log2, "dmarc", stored)
	if len(res3.Problems) == 0 || res3.DMARC != nil {
		t.Fatalf("stored corrupt report must parse with problems: %+v", res3)
	}
	after, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, []byte(broken)) {
		t.Fatal("parsing modified the stored raw report")
	}
}
