// ASN/geo lookup for inbound SMTP (Team Cymru-style DNS TXT; fail-open; TTL cache).
package smtp

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultASNZoneV4       = "origin.asn.cymru.com"
	defaultASNZoneV6       = "origin6.asn.cymru.com"
	defaultASNTimeout      = 2 * time.Second
	defaultASNCacheTTL     = 24 * time.Hour
	defaultASNCacheMissTTL = 15 * time.Minute
	defaultASNCacheMax     = 10000
)

// ASNLookupConfig controls optional client ASN (+ country) resolution at connect.
type ASNLookupConfig struct {
	Enabled         bool
	Timeout         time.Duration
	ZoneIPv4        string
	ZoneIPv6        string
	CacheTTL        time.Duration // positive hits
	CacheMissTTL    time.Duration // empty / DNS fail
	CacheMaxEntries int
	LookupTXT       func(context.Context, string) ([]string, error)
}

type asnCacheEntry struct {
	asn     uint32
	country string
	expire  time.Time
}

// ASNLookup resolves ASN and ISO country for a client IP. Nil or disabled is a no-op.
type ASNLookup struct {
	cfg   ASNLookupConfig
	mu    sync.Mutex
	cache map[string]asnCacheEntry
}

// NewASNLookup builds a lookup helper. Disabled or nil-config returns a no-op instance.
func NewASNLookup(cfg ASNLookupConfig) *ASNLookup {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultASNTimeout
	}
	if cfg.ZoneIPv4 == "" {
		cfg.ZoneIPv4 = defaultASNZoneV4
	}
	if cfg.ZoneIPv6 == "" {
		cfg.ZoneIPv6 = defaultASNZoneV6
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = defaultASNCacheTTL
	}
	if cfg.CacheMissTTL <= 0 {
		cfg.CacheMissTTL = defaultASNCacheMissTTL
	}
	if cfg.CacheMaxEntries <= 0 {
		cfg.CacheMaxEntries = defaultASNCacheMax
	}
	if cfg.LookupTXT == nil {
		cfg.LookupTXT = net.DefaultResolver.LookupTXT
	}
	return &ASNLookup{cfg: cfg, cache: make(map[string]asnCacheEntry)}
}

// Lookup returns ASN id and country code. Failures yield (0, "") so SMTP continues.
func (a *ASNLookup) Lookup(ctx context.Context, clientIP string) (asn uint32, country string) {
	if a == nil || !a.cfg.Enabled {
		return 0, ""
	}
	ip := net.ParseIP(clientIP)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
		return 0, ""
	}
	key := normalizeASNIP(ip)
	if asn, country, ok := a.cacheGet(key); ok {
		return asn, country
	}
	qname, ok := asnQueryName(ip, a.cfg.ZoneIPv4, a.cfg.ZoneIPv6)
	if !ok {
		return 0, ""
	}
	lookupCtx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	txts, err := a.cfg.LookupTXT(lookupCtx, qname)
	if err != nil || len(txts) == 0 {
		a.cachePut(key, 0, "", a.cfg.CacheMissTTL)
		return 0, ""
	}
	asn, country = parseASNCountryTXT(strings.Join(txts, ""))
	ttl := a.cfg.CacheTTL
	if asn == 0 {
		ttl = a.cfg.CacheMissTTL
	}
	a.cachePut(key, asn, country, ttl)
	return asn, country
}

func (a *ASNLookup) cacheGet(key string) (asn uint32, country string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, hit := a.cache[key]
	if !hit || time.Now().After(e.expire) {
		if hit {
			delete(a.cache, key)
		}
		return 0, "", false
	}
	return e.asn, e.country, true
}

func (a *ASNLookup) cachePut(key string, asn uint32, country string, ttl time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if len(a.cache) >= a.cfg.CacheMaxEntries {
		for k, e := range a.cache {
			if now.After(e.expire) {
				delete(a.cache, k)
			}
		}
		// ponytail: if still full, drop arbitrary entries until under cap
		for k := range a.cache {
			if len(a.cache) < a.cfg.CacheMaxEntries {
				break
			}
			delete(a.cache, k)
		}
	}
	a.cache[key] = asnCacheEntry{asn: asn, country: country, expire: now.Add(ttl)}
}

// normalizeASNIP returns a stable cache key for an IP.
func normalizeASNIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// asnQueryName builds "{reversed-ip}.{zone}" for Team Cymru origin TXT lookups.
func asnQueryName(ip net.IP, zoneV4, zoneV6 string) (string, bool) {
	if v4 := ip.To4(); v4 != nil {
		return strconv.Itoa(int(v4[3])) + "." +
			strconv.Itoa(int(v4[2])) + "." +
			strconv.Itoa(int(v4[1])) + "." +
			strconv.Itoa(int(v4[0])) + "." +
			strings.TrimSuffix(zoneV4, ".") + ".", true
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", false
	}
	var b strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		b.WriteByte(hexNibble(v6[i] & 0x0f))
		b.WriteByte('.')
		b.WriteByte(hexNibble(v6[i] >> 4))
		b.WriteByte('.')
	}
	b.WriteString(strings.TrimSuffix(zoneV6, "."))
	b.WriteByte('.')
	return b.String(), true
}

func hexNibble(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + (n - 10)
}

// parseASNCountryTXT parses "ASN | prefix | CC | registry | ..." (pipe-separated).
func parseASNCountryTXT(raw string) (asn uint32, country string) {
	parts := strings.Split(raw, "|")
	if len(parts) < 1 {
		return 0, ""
	}
	asnStr := strings.TrimSpace(parts[0])
	if asnStr == "" {
		return 0, ""
	}
	n, err := strconv.ParseUint(asnStr, 10, 32)
	if err != nil || n == 0 {
		return 0, ""
	}
	if len(parts) >= 3 {
		cc := strings.TrimSpace(parts[2])
		if len(cc) == 2 {
			country = strings.ToUpper(cc)
		}
	}
	return uint32(n), country
}
