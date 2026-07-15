// Bounded outbound HTTP used by antispam rule and redirect lookups.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxRemoteBytes = 1 << 20

// safeHTTPClient blocks non-public targets and bounds redirects and duration.
func safeHTTPClient(timeout time.Duration, maxRedirects int) *http.Client {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if maxRedirects <= 0 {
		maxRedirects = 3
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, addr := range addrs {
				if publicIP(addr.IP) {
					return dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
				}
			}
			return nil, fmt.Errorf("antispam: target is not public")
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			return validateRemoteURL(req.URL, false)
		},
	}
}

// validateRemoteURL restricts schemes and rejects literal private addresses.
func validateRemoteURL(u *url.URL, httpsOnly bool) error {
	if u == nil || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("antispam: invalid remote URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if (httpsOnly && scheme != "https") || (!httpsOnly && scheme != "http" && scheme != "https") {
		return fmt.Errorf("antispam: unsupported remote URL scheme")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !publicIP(ip) {
		return fmt.Errorf("antispam: target is not public")
	}
	return nil
}

func publicIP(ip net.IP) bool {
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

// getRemote returns a bounded response body and final URL.
func getRemote(ctx context.Context, rawURL string, httpsOnly bool, timeout time.Duration, maxRedirects int) ([]byte, *url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	if err := validateRemoteURL(u, httpsOnly); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := safeHTTPClient(timeout, maxRedirects).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, resp.Request.URL, fmt.Errorf("antispam: remote status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteBytes+1))
	if err != nil {
		return nil, resp.Request.URL, err
	}
	if len(body) > maxRemoteBytes {
		return nil, resp.Request.URL, fmt.Errorf("antispam: remote response too large")
	}
	return body, resp.Request.URL, nil
}
