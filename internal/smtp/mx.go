// MX host lookup for outbound SMTP delivery.
package smtp

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

const smtpPort = "25"

// LookupHosts returns MX targets as host:port, lowest preference first.
// Falls back to domain:25 when no MX records exist.
func LookupHosts(ctx context.Context, domain string) ([]string, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return nil, fmt.Errorf("smtp: empty domain")
	}
	records, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return []string{net.JoinHostPort(domain, smtpPort)}, nil
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Pref < records[j].Pref })
	out := make([]string, len(records))
	for i, mx := range records {
		host := strings.TrimSuffix(mx.Host, ".")
		out[i] = net.JoinHostPort(host, smtpPort)
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
