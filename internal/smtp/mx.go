// MX host lookup for outbound SMTP delivery.
package smtp

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
)

const smtpPort = "25"

// errNullMX is a domain that publishes "MX 0 ." (RFC 7505): it accepts no mail at all.
var errNullMX = errors.New("smtp: domain does not accept mail (null MX, RFC 7505; 5.1.10)")

// LookupHosts returns MX targets as host:port, lowest preference first (RFC 5321 5.1).
func LookupHosts(ctx context.Context, domain string) ([]string, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return nil, fmt.Errorf("smtp: empty domain")
	}
	records, err := net.DefaultResolver.LookupMX(ctx, domain)
	return mxTargets(domain, records, err, func() error {
		_, err := net.DefaultResolver.LookupHost(ctx, domain)
		return err
	})
}

// mxTargets turns an MX answer into delivery targets: no MX record means the domain is its own
// implicit MX when it has an address (RFC 5321 5.1), "." is a null MX (RFC 7505), and hosts of equal
// preference are tried in random order (5.1 SHOULD).
func mxTargets(domain string, records []*net.MX, err error, lookupAddr func() error) ([]string, error) {
	var dnsErr *net.DNSError
	if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		return nil, WrapDNS(err)
	}
	if len(records) == 0 {
		if err := lookupAddr(); err != nil {
			return nil, WrapDNS(err)
		}
		return []string{net.JoinHostPort(domain, smtpPort)}, nil
	}
	rand.Shuffle(len(records), func(i, j int) { records[i], records[j] = records[j], records[i] })
	sort.SliceStable(records, func(i, j int) bool { return records[i].Pref < records[j].Pref })
	var out []string
	for _, mx := range records {
		if host := strings.TrimSuffix(mx.Host, "."); host != "" {
			out = append(out, net.JoinHostPort(host, smtpPort))
		}
	}
	if len(out) == 0 {
		return nil, &DeliveryError{Err: errNullMX, Permanent: true}
	}
	return out, nil
}

// DomainFromAddress returns the domain part of an email address.
func DomainFromAddress(addr string) (string, error) {
	addr = strings.TrimSpace(strings.ToLower(addr))
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return "", fmt.Errorf("smtp: invalid address %q", addr)
	}
	return addr[at+1:], nil
}
