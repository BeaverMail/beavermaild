// Derived from rspamd (https://github.com/rspamd/rspamd), Copyright (c) Vsevolod Stakhov and the
// rspamd contributors, Apache License 2.0 (LICENSES/Apache-2.0.txt): src/plugins/lua/url_redirector.lua and conf/modules.d/url_redirector.conf.
// Translated to Go and modified for BeaverMail; see NOTICE.

// URL redirector following (port of rspamd src/plugins/lua/url_redirector.lua) with an SSRF-safe
// HTTP client: public unicast IPs on ports 80/443 only, per-hop timeout, bounded hops, no proxy.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

type redirector struct {
	hosts   map[string]bool
	maxURLs int
	nested  int
	client  *http.Client
}

// reservedNets are non-public ranges beyond what isLocalIP covers (documentation, benchmark, NAT64...).
var reservedNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"0.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "2001:db8::/32", "2002::/16", "100::/64"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// publicIP reports a globally routable unicast address.
func publicIP(ip net.IP) bool {
	if ip == nil || isLocalIP(ip) || !ip.IsGlobalUnicast() {
		return false
	}
	for _, n := range reservedNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

var errForbiddenAddr = errors.New("redirector: destination not allowed")

// safeControl runs after DNS resolution, on the address actually dialled (no rebinding window).
func safeControl(_, address string, _ syscall.RawConn) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if (port != "80" && port != "443") || !publicIP(net.ParseIP(host)) {
		return errForbiddenAddr
	}
	return nil
}

func newRedirector(cfg Config, hosts map[string]bool) *redirector {
	timeout := time.Duration(cfg.URLRedirector.TimeoutMs) * time.Millisecond
	dialer := &net.Dialer{Timeout: timeout, Control: safeControl}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &redirector{hosts: hosts, maxURLs: cfg.URLRedirector.MaxURLs, nested: cfg.URLRedirector.NestedLimit,
		client: &http.Client{Transport: tr, Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (d *redirector) isRedirector(host string) bool { return d.hosts[host] || d.hosts[esld(host)] }

// next returns the Location of a 3xx answer to HEAD u, or nil.
func (d *redirector) next(ctx context.Context, u *msgURL) (*msgURL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaverMail antispam)")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return nil, nil
	}
	loc, err := resp.Location()
	if err != nil {
		return nil, nil
	}
	if n := newURL(loc.String(), u.html); n != nil {
		return n, nil
	}
	return nil, fmt.Errorf("non-HTTP redirect target")
}

// expand follows known redirectors (redirectors_only) and adds the targets to the message URLs,
// so URL and DBL checks see them. URL_REDIRECTOR_NESTED when the chain exceeds nested_limit.
func (d *redirector) expand(ctx context.Context, m *message, r *result) {
	done := 0
	for _, start := range append([]*msgURL(nil), m.urls...) {
		if done >= d.maxURLs || !d.isRedirector(start.host) {
			continue
		}
		done++
		cur := start
		for hop := 0; ; hop++ {
			n, err := d.next(ctx, cur)
			if err != nil {
				logf("url_redirector: %s: %v", cur.host, err)
				break
			}
			if n == nil {
				break
			}
			if hop >= d.nested {
				r.add("URL_REDIRECTOR_NESTED", 1, start.host)
				break
			}
			m.addURL(n.raw, n.html)
			cur = n
		}
	}
}
