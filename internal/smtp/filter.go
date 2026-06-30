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

// Filter action names returned by plugins.
const (
	FilterActionAccept   = "accept"
	FilterActionReject   = "reject"
	FilterActionTempfail = "tempfail"
	FilterActionDiscard  = "discard"
)

// FilterRequest is one SMTP filter check sent to a daemon plugin.
type FilterRequest struct {
	ID        string
	Phase     string
	From      string
	To        []string
	ClientIP  string
	BodyPath  string
	TimeoutMs int
}

// MessageFilter evaluates SMTP transactions via daemon plugins.
type MessageFilter interface {
	Filter(ctx context.Context, req FilterRequest) (action string, err error)
}

// NopFilter accepts all mail (no plugins or plugins not ready).
type NopFilter struct{}

// Filter implements MessageFilter with accept.
func (NopFilter) Filter(context.Context, FilterRequest) (string, error) {
	return FilterActionAccept, nil
}
