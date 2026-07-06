// DNS helpers for EHLO heuristics (reference ehlo.rs DNS checks).
package main

import (
	"context"
	"net"
	"time"
)

func dnsHasAOrMX(ctx context.Context, host string, timeout time.Duration) (hasA, hasMX bool) {
	if host == "" {
		return false, false
	}
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if addrs, err := net.DefaultResolver.LookupIPAddr(c, host); err == nil && len(addrs) > 0 {
		hasA = true
	}
	c2, cancel2 := context.WithTimeout(ctx, timeout)
	defer cancel2()
	if recs, err := net.DefaultResolver.LookupMX(c2, host); err == nil && len(recs) > 0 {
		hasMX = true
	}
	return hasA, hasMX
}
