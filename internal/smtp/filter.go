// SMTP plugin filter types shared between smtp server and pluginhost daemon.
package smtp

import "context"

// Filter phase names for SMTP daemon plugins.
const (
	FilterPhaseConnect = "connect"
	FilterPhaseHelo    = "helo"
	FilterPhaseMail    = "mail"
	FilterPhaseRcpt    = "rcpt"
	FilterPhaseData    = "data"
	FilterPhaseEom     = "eom"
)

// Filter listener kinds sent to plugins (wire: listener).
const (
	FilterListenerInbound    = "inbound"
	FilterListenerSubmission = "submission"
)

// Filter action names returned by plugins.
const (
	FilterActionAccept   = "accept"
	FilterActionReject   = "reject"
	FilterActionTempfail = "tempfail"
	FilterActionDiscard  = "discard"
)

// FilterAuth holds inbound mail-auth results from the host (wire: auth). See .specs/antispam.md.
type FilterAuth struct {
	SPFEhlo     string `json:"spf_ehlo,omitempty"`
	SPFMailFrom string `json:"spf_mail_from,omitempty"`
	DKIM        string `json:"dkim,omitempty"`
	DMARC       string `json:"dmarc,omitempty"`
	DMARCPolicy string `json:"dmarc_policy,omitempty"`
	ARC         string `json:"arc,omitempty"`
}

// FilterRequest is one SMTP filter check sent to a daemon plugin.
type FilterRequest struct {
	ID            string
	Phase         string
	From          string
	To            []string
	ClientIP      string
	BodyPath      string
	TimeoutMs     int
	Listener      string
	TLS           bool
	Authenticated bool
	EHLODomain    string
	IPRevPTR      string
	IPRevResult   string
	ASN           uint32
	Country       string
	Auth          *FilterAuth
}

// FilterOutcome is the plugin decision plus optional score metadata (wire v2.2).
type FilterOutcome struct {
	Action  string
	Score   float64
	Tags    []string
	Headers map[string]string
}

// MessageFilter evaluates SMTP transactions via daemon plugins.
type MessageFilter interface {
	Filter(ctx context.Context, req FilterRequest) (FilterOutcome, error)
}

// NopFilter accepts all mail (no plugins or plugins not ready).
type NopFilter struct{}

// Filter implements MessageFilter with accept.
func (NopFilter) Filter(context.Context, FilterRequest) (FilterOutcome, error) {
	return FilterOutcome{Action: FilterActionAccept}, nil
}
