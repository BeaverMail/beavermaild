// Concurrent connection limiting per client address.
package security

import (
	"net"
	"sync"
)

// IPLimiter caps concurrent holders per client network: one IPv4 address, or one IPv6 /64 (a
// single host usually owns the whole /64). A nil *IPLimiter means unlimited.
type IPLimiter struct {
	max int
	mu  sync.Mutex
	n   map[string]int
}

// NewIPLimiter returns a limiter allowing max holders per network; max <= 0 means unlimited (nil).
func NewIPLimiter(max int) *IPLimiter {
	if max <= 0 {
		return nil
	}
	return &IPLimiter{max: max, n: map[string]int{}}
}

// Acquire takes a slot for ip and returns its release, or false when ip's network is full.
// The release is safe to call more than once.
func (l *IPLimiter) Acquire(ip string) (release func(), ok bool) {
	if l == nil {
		return func() {}, true
	}
	key := ipNetworkKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[key] >= l.max {
		return nil, false
	}
	l.n[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.n[key]--; l.n[key] <= 0 {
				delete(l.n, key)
			}
		})
	}, true
}

// ipNetworkKey groups IPv6 addresses by /64; anything unparsable counts as itself.
func ipNetworkKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String()
}
