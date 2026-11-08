// Derived from rspamd (https://github.com/rspamd/rspamd), Copyright (c) Vsevolod Stakhov and the
// rspamd contributors, Apache License 2.0 (LICENSES/Apache-2.0.txt): src/plugins/lua/rbl.lua and conf/modules.d/rbl.conf.
// Translated to Go and modified for BeaverMail; see NOTICE.

// Spamhaus DNSBL lookups (port of rspamd src/plugins/lua/rbl.lua with the conf/modules.d/rbl.conf
// SPAMHAUS and DBL rules): client and Received IPs against ZEN, domains against DBL.
package main

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Return codes from rspamd conf/modules.d/rbl.conf.
var (
	zenCodes = map[string]string{"127.0.0.2": "SPAMHAUS_SBL", "127.0.0.3": "SPAMHAUS_CSS", "127.0.0.4": "SPAMHAUS_XBL",
		"127.0.0.5": "SPAMHAUS_XBL", "127.0.0.6": "SPAMHAUS_XBL", "127.0.0.7": "SPAMHAUS_XBL", "127.0.0.9": "SPAMHAUS_DROP",
		"127.0.0.10": "SPAMHAUS_PBL", "127.0.0.11": "SPAMHAUS_PBL"}
	dblCodes = map[string]string{"127.0.1.2": "DBL_SPAM", "127.0.1.4": "DBL_PHISH", "127.0.1.5": "DBL_MALWARE",
		"127.0.1.6": "DBL_BOTNET", "127.0.1.102": "DBL_ABUSE", "127.0.1.103": "DBL_ABUSE_REDIR",
		"127.0.1.104": "DBL_ABUSE_PHISH", "127.0.1.105": "DBL_ABUSE_MALWARE", "127.0.1.106": "DBL_ABUSE_BOTNET"}
	// Answers meaning "your query was refused" (public resolver, over quota, IP sent to DBL), never a listing.
	blockedCodes = map[string]bool{"127.255.255.254": true, "127.255.255.255": true, "127.0.1.255": true}
)

type rblTarget struct {
	dbl    bool   // DBL (domain) or ZEN (IP)
	prefix string // ZEN symbol prefix: RBL (client IP) or RECEIVED
	origin string // option prefix, e.g. from, received, helo, url
	value  string // IP or domain, used in options
}

type cacheEntry struct {
	addrs []string
	exp   time.Time
}

type rblClient struct {
	zenZone, dblZone string
	resolver         *net.Resolver
	timeout          time.Duration
	maxLookups       int
	ttl              time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
	// lookup is the DNS seam (tests).
	lookup func(ctx context.Context, name string) ([]string, error)
}

func newRBLClient(cfg Config) *rblClient {
	c := &rblClient{zenZone: "zen.spamhaus.org", dblZone: "dbl.spamhaus.org", resolver: net.DefaultResolver,
		timeout: time.Duration(cfg.RBL.TimeoutMs) * time.Millisecond, maxLookups: cfg.RBL.MaxLookups,
		ttl: time.Duration(cfg.RBL.CacheSecond) * time.Second, cache: map[string]cacheEntry{}}
	if k := cfg.RBL.DQSKey; k != "" {
		c.zenZone, c.dblZone = k+".zen.dq.spamhaus.net", k+".dbl.dq.spamhaus.net"
	}
	if addr := cfg.RBL.Resolver; addr != "" {
		c.resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}
	}
	c.lookup = c.resolver.LookupHost
	return c
}

// reverseIP builds the DNSBL label (inversed octets / nibbles).
func reverseIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
	}
	const hexd = "0123456789abcdef"
	ip = ip.To16()
	b := make([]byte, 0, 64)
	for i := len(ip) - 1; i >= 0; i-- {
		b = append(b, hexd[ip[i]&0xf], '.', hexd[ip[i]>>4], '.')
	}
	return string(b[:len(b)-1])
}

func (c *rblClient) query(t rblTarget) string {
	if t.dbl {
		return t.value + "." + c.dblZone
	}
	return reverseIP(net.ParseIP(t.value)) + "." + c.zenZone
}

// resolve returns the A answers for name; NXDOMAIN is an empty answer, any other failure an error.
func (c *rblClient) resolve(ctx context.Context, name string) (addrs []string, cached bool, err error) {
	now := time.Now()
	c.mu.Lock()
	e, ok := c.cache[name]
	c.mu.Unlock()
	if ok && now.Before(e.exp) {
		return e.addrs, true, nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	addrs, err = c.lookup(ctx, name)
	if err != nil && !isNotFound(err) {
		return nil, false, err
	}
	if err != nil {
		addrs = nil
	}
	c.mu.Lock()
	// shortcut: the cache is dropped wholesale when full; use an LRU if hit rates matter.
	if len(c.cache) > 50000 {
		c.cache = map[string]cacheEntry{}
	}
	c.cache[name] = cacheEntry{addrs: addrs, exp: now.Add(c.ttl)}
	c.mu.Unlock()
	return addrs, false, nil
}

// check runs the lookups in parallel, at most maxLookups uncached queries per message.
func (c *rblClient) check(ctx context.Context, targets []rblTarget, r *result) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]bool{}
	budget := c.maxLookups
	for _, t := range targets {
		q := c.query(t)
		if seen[q] {
			continue
		}
		seen[q] = true
		c.mu.Lock()
		e, hit := c.cache[q]
		c.mu.Unlock()
		if !hit || time.Now().After(e.exp) {
			if budget <= 0 {
				logf("rbl: per-message lookup cap (%d) reached, skipping %s", c.maxLookups, t.origin)
				continue
			}
			budget--
		}
		wg.Add(1)
		go func(t rblTarget, q string) {
			defer wg.Done()
			addrs, _, err := c.resolve(ctx, q)
			if err != nil {
				// A resolver error is never a listing (rbl.lua inserts only *_FAIL, weight 0).
				logf("rbl: lookup for %s:%s failed: %v", t.origin, t.value, redactErr(err, q))
				return
			}
			mu.Lock()
			defer mu.Unlock()
			c.apply(t, addrs, r)
		}(t, q)
	}
	wg.Wait()
}

// redactErr hides the query name (it carries the DQS key) from logged errors.
func redactErr(err error, q string) string { return strings.ReplaceAll(err.Error(), q, "<query>") }

func (c *rblClient) apply(t rblTarget, addrs []string, r *result) {
	codes := zenCodes
	if t.dbl {
		codes = dblCodes
	}
	for _, a := range addrs {
		if blockedCodes[a] {
			logf("rbl: Spamhaus refused the query (%s) for %s: use a local recursive resolver or a DQS key", a, t.origin)
			continue
		}
		s, ok := codes[a]
		if !ok {
			continue // unknown code: rbl.lua ignores it unless `unknown` is set
		}
		if !t.dbl {
			s = t.prefix + "_" + s
		}
		r.add(s, 1, t.origin+":"+t.value)
	}
}

var receivedIPRe = regexp.MustCompile(`\[(?:IPv6:)?([0-9a-fA-F:.]+)\]`)

// rblTargets collects the rbl.lua checks: from (client IP), received, and DBL emails/helo/rdns/replyto/urls.
func (f *Filter) rblTargets(req *request, m *message, local bool) []rblTarget {
	var out []rblTarget
	if !local {
		out = append(out, rblTarget{prefix: "RBL", origin: "from", value: net.ParseIP(req.ClientIP).String()})
	}
	if f.cfg.RBL.Received {
		n := 0
		for _, h := range m.all("Received") {
			from, _, _ := strings.Cut(h.raw, " by ")
			for _, s := range receivedIPRe.FindAllStringSubmatch(from, -1) {
				ip := net.ParseIP(s[1])
				if ip == nil || isLocalIP(ip) || ip.String() == req.ClientIP || n >= 4 {
					continue
				}
				n++
				out = append(out, rblTarget{prefix: "RECEIVED", origin: "received", value: ip.String()})
			}
		}
	}
	addDom := func(origin, d string) {
		d = strings.TrimSuffix(strings.ToLower(d), ".")
		if d == "" || net.ParseIP(d) != nil || !strings.Contains(d, ".") || f.trusted(d) {
			return
		}
		out = append(out, rblTarget{dbl: true, origin: origin, value: d})
	}
	addDom("from_smtp", domainOf(req.From))
	addDom("from_mime", fromDomain(m))
	if l, _, ok := m.addrs("Reply-To"); ok {
		addDom("replyto", domainOf(l[0].Address))
	}
	if isFQDN(req.EHLODomain) {
		addDom("helo", req.EHLODomain)
	}
	addDom("rdns", req.IPRevPTR)
	for _, u := range m.urls {
		addDom("url", esld(u.host))
	}
	return out
}
