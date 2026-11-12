// Outbound connection guard: never let a remote party (DNS of a recipient domain, an MTA-STS host)
// make us connect to our own network.
package security

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ErrPrivateAddr is returned when a connection target is loopback, private, link-local, CGNAT,
// multicast or unspecified.
var ErrPrivateAddr = errors.New("refusing to connect to a loopback, private or link-local address")

// cgnat is RFC 6598 shared address space (carrier-grade NAT), not covered by net.IP.IsPrivate.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// IsInternalIP reports whether ip belongs to a network outbound mail must not reach.
func IsInternalIP(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() || cgnat.Contains(ip) || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// RejectInternalDial is a net.Dialer.Control hook. It runs at connect time, after DNS, so a name that
// resolves (or rebinds) to an internal address is refused too.
func RejectInternalDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if IsInternalIP(net.ParseIP(host)) {
		return fmt.Errorf("%w: %s", ErrPrivateAddr, host)
	}
	return nil
}
