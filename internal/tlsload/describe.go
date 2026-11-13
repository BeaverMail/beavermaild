package tlsload

import (
	"crypto/tls"
	"net"
)

// Describe returns "<version> <IANA cipher suite>" for a TLS connection, "none" otherwise: the TLS
// cipher information RFC 8314 4 asks servers to log with connection and authentication logs.
func Describe(conn net.Conn) string {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return "none"
	}
	st := tc.ConnectionState()
	return tls.VersionName(st.Version) + " " + tls.CipherSuiteName(st.CipherSuite)
}
