// Outbound delivery via configured relay or recipient MX hosts.
package smtp

import (
	"context"
	"errors"
)

// RemoteConfig holds relay address and optional TLS/AUTH for outbound submission.
type RemoteConfig struct {
	Relay        string
	RelayOptions ClientOptions
}

// DeliverRemote submits mail using relay when set, otherwise MX lookup on rcptTo domain.
func DeliverRemote(ctx context.Context, cfg RemoteConfig, mailFrom, rcptTo string, data []byte) error {
	if cfg.Relay != "" {
		return Send(ctx, cfg.Relay, mailFrom, rcptTo, data, cfg.RelayOptions)
	}
	domain, err := DomainFromAddress(rcptTo)
	if err != nil {
		return err
	}
	hosts, err := LookupHosts(ctx, domain)
	if err != nil {
		return err
	}
	return deliverMX(ctx, hosts, mailFrom, rcptTo, data)
}

func deliverMX(ctx context.Context, hosts []string, mailFrom, rcptTo string, data []byte) error {
	mxOpts := ClientOptions{OpportunisticSTARTTLS: true}
	var last error
	for _, host := range hosts {
		err := Send(ctx, host, mailFrom, rcptTo, data, mxOpts)
		if err == nil {
			return nil
		}
		if deliveryPermanent(err) {
			return err
		}
		if shouldTryNextMX(err) {
			last = err
			continue
		}
		return err
	}
	if last != nil {
		return last
	}
	return errors.New("smtp: no MX hosts")
}
