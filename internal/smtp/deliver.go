// Outbound delivery via configured relay or recipient MX hosts.
package smtp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/dnsname"
	"github.com/BeaverMail/beavermaild/internal/mtasts"
)

// RemoteConfig holds relay address and optional TLS/AUTH for outbound submission.
type RemoteConfig struct {
	Relay        string
	RelayOptions ClientOptions
	MXOptions    ClientOptions // direct MX delivery (EHLO name, private-address guard)
	MTASTS       *mtasts.Resolver
	// TLSPolicy maps a recipient domain (A-labels, lowercase) to TLSEncrypt or TLSVerify: the static
	// per-destination TLS requirement of RFC 3207 6 (smtp.tls_policy).
	TLSPolicy map[string]string
}

// Static TLS levels for a recipient domain (smtp.tls_policy, as Postfix smtp_tls_policy_maps).
const (
	TLSEncrypt = "encrypt" // STARTTLS mandatory, certificate not checked
	TLSVerify  = "verify"  // STARTTLS mandatory, certificate valid for the MX host name
)

// tlsLevel returns the static TLS level for domain, "" when none is configured.
func (cfg RemoteConfig) tlsLevel(domain string) string {
	return cfg.TLSPolicy[dnsname.ToASCII(strings.TrimSuffix(strings.ToLower(domain), "."))]
}

// DeliverRemote submits mail using relay when set, otherwise MX lookup on rcptTo domain.
// On success it returns "host: final server reply" for the delivery record.
func DeliverRemote(ctx context.Context, cfg RemoteConfig, mailFrom, rcptTo string, data []byte) (string, error) {
	if cfg.Relay != "" {
		opts, err := relayOptionsForPolicy(ctx, cfg)
		if err != nil {
			return "", err
		}
		reply, err := SendReply(ctx, cfg.Relay, mailFrom, rcptTo, data, opts)
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
	return deliverMX(ctx, hosts, mailFrom, rcptTo, data, mxOptionsForPolicy(cfg.MXOptions, policy, cfg.tlsLevel(domain)))
}

// relayOptionsForPolicy applies MTA-STS to a smart host: its domain is the Policy Domain (RFC 8461
// 3.4). Under enforce it must match an mx pattern, offer STARTTLS and present a valid certificate,
// whatever the relay settings say. Address literals have no policy; a loopback relay is local.
func relayOptionsForPolicy(ctx context.Context, cfg RemoteConfig) (ClientOptions, error) {
	opts := cfg.RelayOptions
	host, _, err := net.SplitHostPort(cfg.Relay)
	if err != nil {
		host = cfg.Relay
	}
	if cfg.MTASTS == nil || net.ParseIP(host) != nil || IsLoopbackAddr(cfg.Relay) {
		return opts, nil
	}
	policy, err := cfg.MTASTS.Policy(ctx, host)
	if err != nil || !policy.Enforce() {
		return opts, err
	}
	if !policy.AllowsMX(host) {
		return opts, tlsFailure{errors.New("mta-sts: smart host does not match the policy of its domain")}
	}
	opts.STARTTLS, opts.RequireTLS, opts.TLSInsecureSkipVerify = true, true, false
	return opts, nil
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
		return nil, tlsFailure{errors.New("mta-sts: no MX host matches policy")}
	}
	return out, nil
}

// mxOptionsForPolicy: without an explicit policy TLS to the MX is opportunistic and unauthenticated
// (RFC 7435 3: default authentication checks "must be disabled or configured to soft-fail"; MX
// indirection precludes authentication anyway, RFC 7672 1.3). Explicit policies preempt it and the
// strongest wins: the static level (RFC 3207 6) requires TLS, with a valid certificate for "verify";
// MTA-STS enforce requires both (RFC 8461 4.2, 5).
func mxOptionsForPolicy(base ClientOptions, policy *mtasts.Policy, level string) ClientOptions {
	opts := ClientOptions{
		OpportunisticSTARTTLS: true,
		TLSInsecureSkipVerify: true,
		HeloName:              base.HeloName,
		RejectPrivate:         base.RejectPrivate,
	}
	if level != "" {
		opts.RequireTLS = true
		opts.TLSInsecureSkipVerify = level != TLSVerify
	}
	if policy.Enforce() {
		opts.RequireTLS = true
		opts.TLSInsecureSkipVerify = false
	}
	return opts
}

func deliverMX(ctx context.Context, hosts []string, mailFrom, rcptTo string, data []byte, opts ClientOptions) (string, error) {
	mxOpts := opts
	if !mxOpts.OpportunisticSTARTTLS && !mxOpts.RequireTLS {
		mxOpts.OpportunisticSTARTTLS = true
	}
	var last error
	allPrivate := true
	for _, host := range hosts {
		reply, err := SendReply(ctx, host, mailFrom, rcptTo, data, mxOpts)
		if err == nil {
			return host + ": " + reply, nil
		}
		allPrivate = allPrivate && errors.Is(err, errPrivateAddr)
		if deliveryPermanent(err) {
			return "", err
		}
		if shouldTryNextMX(err) {
			last = err
			continue
		}
		return "", err
	}
	if last != nil && allPrivate {
		// Every MX is on our own network: retrying will not change the DNS answer we refuse.
		return "", &DeliveryError{Err: last, Permanent: true}
	}
	if last != nil {
		return "", last
	}
	return "", fmt.Errorf("smtp: no MX hosts")
}
