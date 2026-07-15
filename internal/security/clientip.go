// Client IP helpers for connection-scoped security policy.
package security

import "net"

// ClientIP returns the remote host from conn.RemoteAddr (no port).
func ClientIP(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
