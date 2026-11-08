// DMARC aggregate (RFC 7489) and TLS-RPT (RFC 8460) parsing of raw report messages
// as stored by SaveDomainReport. Parsing problems are non-fatal: they are collected
// in ParsedReport.Problems and logged at Warn; the raw .eml is never touched and no
// field is ever invented — unparsable input yields empty pointers, not guesses.
package directory

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"

	"log/slog"
)

// ParsedReport is the honest result of parsing one raw report message.
// DMARC/TLS are only set when the payload actually parsed; otherwise Problems
// explains why and Format keeps the identified payload format (or "unknown").
type ParsedReport struct {
	Kind     string        `json:"kind"`               // dmarc|tls (as passed in)
	Format   string        `json:"format"`             // sniffed payload format: xml|json|unknown
	DMARC    *DMARCReport  `json:"dmarc,omitempty"`    // set only for kind=xml payloads that parsed
	TLS      *TLSRPTReport `json:"tls,omitempty"`      // set only for kind=json payloads that parsed
	Problems []string      `json:"problems,omitempty"` // non-fatal parse issues, also logged at Warn
}

// ParseReport parses one raw report message of the given kind ("dmarc" or "tls")
// into a typed report. Errors never abort: each problem is appended to Problems and
// logged at Warn, and the raw message remains the source of truth.
func ParseReport(log *slog.Logger, kind string, raw []byte) ParsedReport {
	if log == nil {
		log = slog.Default()
	}
	res := ParsedReport{Kind: kind, Format: "unknown"}
	want := expectedReportFormat(kind)
	if want == "" {
		res.Problems = append(res.Problems, fmt.Sprintf("unknown report kind %q", kind))
	}
	payloads, problems := reportPayloads(raw)
	res.Problems = append(res.Problems, problems...)
	for _, p := range payloads {
		format := sniffReportFormat(p.data)
		if format != want {
			continue
		}
		res.Format = format
		if err := res.parsePayload(format, p.data); err != nil {
			res.Problems = append(res.Problems, format+": "+err.Error())
			continue
		}
		break
	}
	if want != "" && res.DMARC == nil && res.TLS == nil && len(res.Problems) == 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("no %s payload found in message", want))
	}
	for _, p := range res.Problems {
		log.Warn("report parse", "kind", kind, "problem", p)
	}
	return res
}

// expectedReportFormat maps a report kind to its payload format.
func expectedReportFormat(kind string) string {
	switch kind {
	case "dmarc":
		return "xml"
	case "tls":
		return "json"
	}
	return ""
}

// parsePayload decodes data into the struct matching format. The result pointer is
// only set on success; a document that is not actually a report is rejected.
func (r *ParsedReport) parsePayload(format string, data []byte) error {
	switch format {
	case "xml":
		var rep DMARCReport
		if err := xml.Unmarshal(data, &rep); err != nil {
			return err
		}
		if rep.ReportMetadata.ReportID == "" && rep.PolicyPublished.Domain == "" {
			return errors.New("not a DMARC aggregate report")
		}
		r.DMARC = &rep
	case "json":
		var rep TLSRPTReport
		if err := json.Unmarshal(data, &rep); err != nil {
			return err
		}
		if rep.OrganizationName == "" && rep.ReportID == "" && len(rep.Policies) == 0 {
			return errors.New("not a TLS-RPT report")
		}
		r.TLS = &rep
	}
	return nil
}

// reportPayload is one decoded MIME leaf body (decompressed when gzipped).
type reportPayload struct {
	contentType string
	filename    string
	data        []byte
}

// reportPayloads walks the message MIME tree and returns the decoded leaf bodies.
// Problems (unreadable message, bad encodings, broken gzip) are non-fatal notes.
func reportPayloads(raw []byte) ([]reportPayload, []string) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, []string{"message: " + err.Error()}
	}
	var out []reportPayload
	var problems []string
	walkMIMEPart(textproto.MIMEHeader(msg.Header), readAll(msg.Body), &out, &problems)
	return out, problems
}

// walkMIMEPart decodes one MIME part and recurses into multipart bodies.
func walkMIMEPart(header textproto.MIMEHeader, body []byte, out *[]reportPayload, problems *[]string) {
	ct, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil {
		ct = ""
	}
	body = decodeTransferEncoding(header.Get("Content-Transfer-Encoding"), body, problems)
	_, dispParams, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
	filename := dispParams["filename"]
	if filename == "" {
		filename = params["name"]
	}
	if strings.HasPrefix(ct, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			*problems = append(*problems, "mime: multipart without boundary")
			return
		}
		mr := multipart.NewReader(bytes.NewReader(body), boundary)
		for {
			part, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				*problems = append(*problems, "mime: "+err.Error())
				return
			}
			walkMIMEPart(part.Header, readAll(part), out, problems)
		}
	}
	data := body
	if isGzip(ct, filename, data) {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			*problems = append(*problems, "gzip: "+err.Error())
		} else {
			data = readAll(gz)
			if err := gz.Close(); err != nil {
				*problems = append(*problems, "gzip: "+err.Error())
			}
		}
	}
	*out = append(*out, reportPayload{contentType: ct, filename: filename, data: data})
}

// decodeTransferEncoding undoes the Content-Transfer-Encoding of a part body.
// A broken encoding is a note, not a failure: the raw body is kept as-is.
func decodeTransferEncoding(enc string, body []byte, problems *[]string) []byte {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		dec, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(body)))
		if err != nil {
			*problems = append(*problems, "mime: "+err.Error())
			return body
		}
		return dec
	case "quoted-printable":
		return readAll(quotedprintable.NewReader(bytes.NewReader(body)))
	}
	return body
}

// isGzip reports whether a part body is gzip: by media type, by attachment name,
// or by magic bytes (covers application/octet-stream senders).
func isGzip(contentType, filename string, data []byte) bool {
	switch contentType {
	case "application/gzip", "application/x-gzip", "application/gzip-compressed":
		return true
	}
	if strings.HasSuffix(strings.ToLower(filename), ".gz") {
		return true
	}
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// sniffReportFormat identifies the payload format by its first byte.
// ponytail: naive sniff; exotic prologs (BOM + comment) read as unknown, which is
// the honest answer over a guess.
func sniffReportFormat(data []byte) string {
	trim := bytes.TrimLeft(data, " \t\r\n")
	switch {
	case bytes.HasPrefix(trim, []byte("<")):
		return "xml"
	case bytes.HasPrefix(trim, []byte("{")), bytes.HasPrefix(trim, []byte("[")):
		return "json"
	}
	return "unknown"
}

func readAll(r io.Reader) []byte {
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.Bytes()
}

// DMARCReport is a DMARC aggregate report (RFC 7489 Appendix C). Verbatim string
// fields stay as sent: nothing is normalized into invented values.
type DMARCReport struct {
	ReportMetadata  DMARCReportMetadata  `xml:"report_metadata"`
	PolicyPublished DMARCPolicyPublished `xml:"policy_published"`
	Records         []DMARCRecord        `xml:"record"`
}

type DMARCReportMetadata struct {
	OrgName          string         `xml:"org_name"`
	Email            string         `xml:"email"`
	ExtraContactInfo string         `xml:"extra_contact_info"`
	ReportID         string         `xml:"report_id"`
	DateRange        DMARCDateRange `xml:"date_range"`
}

// DMARCDateRange keeps the epoch seconds verbatim as sent (RFC 7489 date-time).
type DMARCDateRange struct {
	Begin string `xml:"begin"`
	End   string `xml:"end"`
}

type DMARCPolicyPublished struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
	PCT    int    `xml:"pct"`
}

type DMARCRecord struct {
	Row         DMARCRow         `xml:"row"`
	Identifiers DMARCIdentifiers `xml:"identifiers"`
	AuthResults DMARCAuthResults `xml:"auth_results"`
}

type DMARCRow struct {
	SourceIP        string               `xml:"source_ip"`
	Count           int                  `xml:"count"`
	PolicyEvaluated DMARCPolicyEvaluated `xml:"policy_evaluated"`
}

type DMARCPolicyEvaluated struct {
	Disposition string        `xml:"disposition"`
	DKIM        string        `xml:"dkim"`
	SPF         string        `xml:"spf"`
	Reasons     []DMARCReason `xml:"reason"`
}

type DMARCReason struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment"`
}

type DMARCIdentifiers struct {
	EnvelopeTo   string `xml:"envelope_to"`
	EnvelopeFrom string `xml:"envelope_from"`
	HeaderFrom   string `xml:"header_from"`
}

type DMARCAuthResults struct {
	DKIM []DMARCDKIMAuth `xml:"dkim"`
	SPF  []DMARCSPFAuth  `xml:"spf"`
}

type DMARCDKIMAuth struct {
	Domain      string `xml:"domain"`
	Selector    string `xml:"selector"`
	Result      string `xml:"result"`
	HumanResult string `xml:"human_result"`
}

type DMARCSPFAuth struct {
	Domain string `xml:"domain"`
	Scope  string `xml:"scope"`
	Result string `xml:"result"`
}

// TLSRPTReport is a TLS-RPT report (RFC 8460 Section 2.1/2.2).
type TLSRPTReport struct {
	OrganizationName string          `json:"organization-name"`
	DateRange        TLSRPTDateRange `json:"date-range"`
	ContactInfo      string          `json:"contact-info"`
	ReportID         string          `json:"report-id"`
	Policies         []TLSRPTPolicy  `json:"policies"`
}

type TLSRPTDateRange struct {
	StartDatetime string `json:"start-datetime"`
	EndDatetime   string `json:"end-datetime"`
}

type TLSRPTPolicy struct {
	Policy         TLSRPTPolicyInfo `json:"policy"`
	Summary        TLSRPTSummary    `json:"summary"`
	FailureDetails []TLSRPTFailure  `json:"failure-details"`
}

type TLSRPTPolicyInfo struct {
	PolicyType   string   `json:"policy-type"` // tlsa|sts|no-policy-found
	PolicyString []string `json:"policy-string"`
	PolicyDomain string   `json:"policy-domain"`
}

type TLSRPTSummary struct {
	TotalSuccessfulSessionCount int `json:"total-successful-session-count"`
	TotalFailureSessionCount    int `json:"total-failure-session-count"`
}

type TLSRPTFailure struct {
	ResultType            string `json:"result-type"`
	SendingMTAIP          string `json:"sending-mta-ip"`
	ReceivingMXHostname   string `json:"receiving-mx-hostname"`
	ReceivingMXIP         string `json:"receiving-mx-ip"`
	ReceivingIP           string `json:"receiving-ip"`
	FailedSessionCount    int    `json:"failed-session-count"`
	AdditionalInformation string `json:"additional-information"`
	FailureErrorCode      string `json:"failure-error-code"`
}
