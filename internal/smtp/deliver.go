// Outbound delivery via configured relay or recipient MX hosts.
package smtp

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/BeaverMail/beaver/internal/mtasts"
)

// RemoteConfig holds relay address and optional TLS/AUTH for outbound submission.
type RemoteConfig struct {
	Relay        string
	RelayOptions ClientOptions
	MXOptions    ClientOptions // TLS verify policy for direct MX delivery
	MTASTS       *mtasts.Resolver
}

// DeliverRemote submits mail using relay when set, otherwise MX lookup on rcptTo domain.
// On success it returns "host: final server reply" for the delivery record.
func DeliverRemote(ctx context.Context, cfg RemoteConfig, mailFrom, rcptTo string, data []byte) (string, error) {
	if cfg.Relay != "" {
		reply, err := SendReply(ctx, cfg.Relay, mailFrom, rcptTo, data, cfg.RelayOptions)
		if err != nil {
			return "", err
		}
		return cfg.Relay + ": " + reply, nil
	}
	domain, err := DomainFromAddress(rcptTo)
	if err != nil {
		return "", err
	}
	var policy *mtasts.Policy
	if cfg.MTASTS != nil {
		policy, err = cfg.MTASTS.Policy(ctx, domain)
		if err != nil {
			return "", err
		}
	}
	hosts, err := LookupHosts(ctx, domain)
	if err != nil {
		return "", err
	}
	hosts, err = filterMXForMTASTS(hosts, policy)
	if err != nil {
		return "", err
	}
	return deliverMX(ctx, hosts, mailFrom, rcptTo, data, mxOptionsForPolicy(cfg.MXOptions, policy))
}

func filterMXForMTASTS(hosts []string, policy *mtasts.Policy) ([]string, error) {
	if policy == nil || !policy.Enforce() {
		return hosts, nil
	}
	out := make([]string, 0, len(hosts))
	for _, addr := range hosts {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		if policy.AllowsMX(host) {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		return nil, &DeliveryError{Err: errors.New("mta-sts: no MX host matches policy"), Permanent: true}
	}
	return out, nil
}

func mxOptionsForPolicy(base ClientOptions, policy *mtasts.Policy) ClientOptions {
	opts := ClientOptions{
		OpportunisticSTARTTLS: true,
		TLSInsecureSkipVerify: base.TLSInsecureSkipVerify,
		HeloName:              base.HeloName,
	}
	if policy != nil && policy.Enforce() {
		opts.MTASTSRequireTLS = true
		opts.TLSInsecureSkipVerify = false
	}
	return opts
}

func deliverMX(ctx context.Context, hosts []string, mailFrom, rcptTo string, data []byte, opts ClientOptions) (string, error) {
	mxOpts := opts
	if !mxOpts.OpportunisticSTARTTLS && !mxOpts.MTASTSRequireTLS {
		mxOpts.OpportunisticSTARTTLS = true
	}
	var last error
	for _, host := range hosts {
		reply, err := SendReply(ctx, host, mailFrom, rcptTo, data, mxOpts)
		if err == nil {
			return host + ": " + reply, nil
		}
		if deliveryPermanent(err) {
			return "", err
		}
		if shouldTryNextMX(err) {
			last = err
			continue
		}
		return "", err
	}
	if last != nil {
		return "", last
	}
	return "", fmt.Errorf("smtp: no MX hosts")
}
