package spf

import (
	"context"
	"errors"
	"net"

	"github.com/miekg/dns"
)

// Resolver answers one DNS query. The response carries the RCODE: SPF must tell NXDOMAIN (3) from
// other failures (4.4, 5), which net cannot.
type Resolver interface {
	Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
}

// SystemResolver queries the name servers of /etc/resolv.conf, over UDP and TCP when truncated.
// The configuration is read once, when built: a lazy first-use setup raced between sessions.
type SystemResolver struct {
	servers []string
	err     error
}

// NewSystemResolver reads /etc/resolv.conf. A missing or empty file makes every query fail
// (temperror), it does not panic.
func NewSystemResolver() *SystemResolver {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return &SystemResolver{err: err}
	}
	r := &SystemResolver{}
	for _, s := range cfg.Servers {
		r.servers = append(r.servers, net.JoinHostPort(s, cfg.Port))
	}
	if len(r.servers) == 0 {
		r.err = errors.New("spf: no name server in /etc/resolv.conf")
	}
	return r
}

// Resolve tries each server in turn until one answers.
func (r *SystemResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if r.err != nil {
		return nil, r.err
	}
	q = q.Copy()
	q.SetEdns0(4096, false)
	err := errors.New("spf: no answer")
	for _, s := range r.servers {
		var m *dns.Msg
		m, _, err = (&dns.Client{Net: "udp"}).ExchangeContext(ctx, q, s)
		if err == nil && m.Truncated {
			m, _, err = (&dns.Client{Net: "tcp"}).ExchangeContext(ctx, q, s)
		}
		if err == nil {
			return m, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, err
}
