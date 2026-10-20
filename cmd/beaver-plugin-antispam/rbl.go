// DNS RBL lookups for beaver-plugin-antispam.
package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type rblChecker struct {
	mu       sync.Mutex
	cache    map[string]cacheEntry
	lookupIP func(context.Context, string, string) ([]net.IP, error)
}

type cacheEntry struct {
	listed bool
	tag    string
	expire time.Time
}

func newRBLChecker() *rblChecker {
	return &rblChecker{
		cache:    make(map[string]cacheEntry),
		lookupIP: net.DefaultResolver.LookupIP,
	}
}

func (r *rblChecker) checkIPStr(clientIP string, cfg rblConfig) (listed bool, tag string, dnsFail bool) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, "", false
	}
	return r.checkIP(ip, cfg)
}

func (r *rblChecker) checkDomain(domain string, cfg rblConfig) (listed bool, tag string, dnsFail bool) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" || !cfg.Enabled || len(cfg.Zones) == 0 {
		return false, "", false
	}
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	for _, zone := range cfg.Zones {
		qname := domain + "." + queryZone(zone, cfg)
		if hit, t, fail := r.query(qname, zone, timeout, cfg); fail {
			return false, "", true
		} else if hit {
			return true, t, false
		}
	}
	return false, "", false
}

func (r *rblChecker) checkIP(ip net.IP, cfg rblConfig) (listed bool, tag string, dnsFail bool) {
	if ip == nil || !cfg.Enabled || len(cfg.Zones) == 0 {
		return false, "", false
	}
	if ip.IsLoopback() {
		return false, "", false
	}
	rev := reverseIP(ip)
	if rev == "" {
		return false, "", false
	}
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	for _, zone := range cfg.Zones {
		qname := rev + "." + queryZone(zone, cfg)
		if hit, t, fail := r.query(qname, zone, timeout, cfg); fail {
			return false, "", true
		} else if hit {
			return true, t, false
		}
	}
	return false, "", false
}

func (r *rblChecker) query(qname, zone string, timeout time.Duration, cfg rblConfig) (listed bool, tag string, dnsFail bool) {
	r.mu.Lock()
	if e, ok := r.cache[qname]; ok && time.Now().Before(e.expire) {
		r.mu.Unlock()
		return e.listed, e.tag, false
	}
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := r.lookupIP(ctx, "ip4", qname)
	if err != nil {
		if derr, ok := err.(*net.DNSError); ok && derr.IsNotFound {
			r.store(qname, false, "", cfg.CacheTTLMissSec)
			return false, "", false
		}
		return false, "", true
	}
	for _, a := range addrs {
		v4 := a.To4()
		if v4 == nil {
			continue
		}
		if isDNSBLError(v4) {
			return false, "", true
		}
		if v4[0] == 127 && rblCodeListed(zone, v4, cfg) {
			tag = rblTag(zone, cfg)
			r.store(qname, true, tag, cfg.CacheTTLListedSec)
			return true, tag, false
		}
	}
	r.store(qname, false, "", cfg.CacheTTLMissSec)
	return false, "", false
}

func (r *rblChecker) store(key string, listed bool, tag string, ttlSec int) {
	if ttlSec <= 0 {
		ttlSec = 3600
	}
	r.mu.Lock()
	r.cache[key] = cacheEntry{listed: listed, tag: tag, expire: time.Now().Add(time.Duration(ttlSec) * time.Second)}
	r.mu.Unlock()
}

// isDNSBLError reports DNSBL error replies, which are not listings: 127.255.255.x
// (Spamhaus: query via public/open resolver, rate limited, unknown zone) and 127.0.1.255
// (Spamhaus DBL: IP address queried as a domain). Counting them would reject all mail.
func isDNSBLError(v4 net.IP) bool {
	return v4[0] == 127 && ((v4[1] == 255 && v4[2] == 255) || (v4[1] == 0 && v4[2] == 1 && v4[3] == 255))
}

// rblCodeListed reports whether reply v4 counts as a listing for zone (see rblConfig.ZoneCodes).
func rblCodeListed(zone string, v4 net.IP, cfg rblConfig) bool {
	codes, ok := cfg.ZoneCodes[strings.TrimSuffix(zone, ".")]
	if !ok {
		return true
	}
	for _, spec := range codes {
		base, hi, isRange := strings.Cut(strings.TrimSpace(spec), "-")
		ip := net.ParseIP(base).To4()
		if ip == nil {
			continue
		}
		if !isRange {
			if ip.Equal(v4) {
				return true
			}
			continue
		}
		top, err := strconv.Atoi(hi)
		if err == nil && ip[0] == v4[0] && ip[1] == v4[1] && ip[2] == v4[2] && int(v4[3]) >= int(ip[3]) && int(v4[3]) <= top {
			return true
		}
	}
	return false
}

// queryZone returns the DNS zone to query: a *.spamhaus.org zone goes through DQS
// when a key is configured, any other zone is used as is.
func queryZone(zone string, cfg rblConfig) string {
	zone = strings.TrimSuffix(zone, ".")
	key := strings.TrimSpace(cfg.SpamhausDQSKey)
	if name, ok := strings.CutSuffix(zone, ".spamhaus.org"); ok && key != "" {
		return key + "." + name + ".dq.spamhaus.net"
	}
	return zone
}

func rblTag(zone string, cfg rblConfig) string {
	zone = strings.TrimSuffix(zone, ".")
	if cfg.TagAliases != nil {
		if t, ok := cfg.TagAliases[zone]; ok && t != "" {
			return t
		}
	}
	prefix := cfg.TagPrefix
	if prefix == "" {
		prefix = "RBL_"
	}
	alias := strings.Split(zone, ".")[0]
	return prefix + strings.ToUpper(strings.ReplaceAll(alias, ".", "_"))
}

func reverseIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return strings.Join([]string{
			itoa(int(v4[3])), itoa(int(v4[2])), itoa(int(v4[1])), itoa(int(v4[0])),
		}, ".")
	}
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	var parts []string
	for i := len(ip) - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", ip[i]&0x0f), fmt.Sprintf("%x", ip[i]>>4))
	}
	return strings.Join(parts, ".")
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
