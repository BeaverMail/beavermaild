// JSON protocol types for SMTP daemon plugins.
package daemon

import "github.com/BeaverMail/beaver/internal/smtp"

// ReadyLine is the first JSON line a daemon plugin sends after connecting.
type ReadyLine struct {
	Status         string   `json:"status"`
	Capabilities   []string `json:"capabilities,omitempty"`
	MaxConnections int      `json:"max_connections,omitempty"`
}

// wireAuth mirrors smtp.FilterAuth on the JSON wire.
type wireAuth struct {
	SPFEhlo     string `json:"spf_ehlo,omitempty"`
	SPFMailFrom string `json:"spf_mail_from,omitempty"`
	DKIM        string `json:"dkim,omitempty"`
	DMARC       string `json:"dmarc,omitempty"`
	DMARCPolicy string `json:"dmarc_policy,omitempty"`
}

// FilterRequest is the host-to-plugin filter JSON line (protocol v2.2).
type FilterRequest struct {
	ID            string   `json:"id"`
	Phase         string   `json:"phase"`
	From          string   `json:"from,omitempty"`
	To            []string `json:"to,omitempty"`
	ClientIP      string   `json:"client_ip,omitempty"`
	BodyPath      string   `json:"body_path,omitempty"`
	TimeoutMs     int      `json:"timeout_ms,omitempty"`
	Listener      string   `json:"listener,omitempty"`
	TLS           bool     `json:"tls,omitempty"`
	Authenticated bool     `json:"authenticated,omitempty"`
	EHLODomain    string   `json:"ehlo_domain,omitempty"`
	IPRevPTR      string   `json:"iprev_ptr,omitempty"`
	IPRevResult   string   `json:"iprev_result,omitempty"`
	ASN           uint32   `json:"asn,omitempty"`
	Country       string   `json:"country,omitempty"`
	Auth          *wireAuth `json:"auth,omitempty"`
}

// FilterResponse is the plugin-to-host filter JSON line (protocol v2.2).
type FilterResponse struct {
	ID      string            `json:"id"`
	Action  string            `json:"action"`
	Score   float64           `json:"score,omitempty"`
	Tags    []string          `json:"tags,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// encodeFilterRequest maps internal filter state to the wire DTO.
func encodeFilterRequest(req smtp.FilterRequest) FilterRequest {
	out := FilterRequest{
		ID:            req.ID,
		Phase:         req.Phase,
		From:          req.From,
		To:            req.To,
		ClientIP:      req.ClientIP,
		BodyPath:      req.BodyPath,
		TimeoutMs:     req.TimeoutMs,
		Listener:      req.Listener,
		TLS:           req.TLS,
		Authenticated: req.Authenticated,
		EHLODomain:    req.EHLODomain,
		IPRevPTR:      req.IPRevPTR,
		IPRevResult:   req.IPRevResult,
		ASN:           req.ASN,
		Country:       req.Country,
	}
	if req.Auth != nil {
		out.Auth = &wireAuth{
			SPFEhlo:     req.Auth.SPFEhlo,
			SPFMailFrom: req.Auth.SPFMailFrom,
			DKIM:        req.Auth.DKIM,
			DMARC:       req.Auth.DMARC,
			DMARCPolicy: req.Auth.DMARCPolicy,
		}
	}
	return out
}

// decodeFilterOutcome maps the wire response to smtp.FilterOutcome.
func decodeFilterOutcome(resp FilterResponse) smtp.FilterOutcome {
	return smtp.FilterOutcome{
		Action:  resp.Action,
		Score:   resp.Score,
		Tags:    resp.Tags,
		Headers: resp.Headers,
	}
}
