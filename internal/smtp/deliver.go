// Outbound delivery via configured relay or recipient MX hosts.
package smtp

import (
	"context"
	"errors"
)

// DeliverRemote submits mail using relay when set, otherwise MX lookup on rcptTo domain.
func DeliverRemote(ctx context.Context, relay, mailFrom, rcptTo string, data []byte) error {
	if relay != "" {
		return Send(ctx, relay, mailFrom, rcptTo, data, ClientOptions{})
	}
	domain, err := DomainFromAddress(rcptTo)
	if err != nil {
		return err
	}
	hosts, err := LookupHosts(ctx, domain)
	if err != nil {
		return err
	}
	var last error
	for _, host := range hosts {
		err := Send(ctx, host, mailFrom, rcptTo, data, ClientOptions{})
		if err == nil {
			return nil
		}
		if deliveryPermanent(err) {
			return err
		}
		last = err
	}
	if last != nil {
		return last
	}
	return errors.New("smtp: no MX hosts")
}

func deliveryPermanent(err error) bool {
	type permanent interface {
		error
		DeliveryPermanent() bool
	}
	var p permanent
	if errors.As(err, &p) {
		return p.DeliveryPermanent()
	}
	return false
}
