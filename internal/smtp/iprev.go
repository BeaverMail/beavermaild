// Reverse DNS (PTR) lookup for SMTP client IP used by antispam filter wire.
package smtp

import (
	"context"
	"net"
	"strings"
	"time"
)

// IPRev outcomes on filter wire (plugin maps to RDNS_* tags).
const (
	IPRevPass       = "pass"
	IPRevNone       = "none"
	IPRevTempError  = "temperror"
)

// LookupIPRev performs PTR lookup for clientIP with timeout.
func LookupIPRev(ctx context.Context, clientIP string, timeout time.Duration) (ptr string, result string) {
	ip := net.ParseIP(clientIP)
	if ip == nil || ip.IsLoopback() {
		return "", IPRevPass
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, clientIP)
	if err != nil {
		if derr, ok := err.(*net.DNSError); ok && derr.IsNotFound {
			return "", IPRevNone
		}
		return "", IPRevTempError
	}
	if len(names) == 0 {
		return "", IPRevNone
	}
	ptr = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(names[0])), ".")
	return ptr, IPRevPass
}
