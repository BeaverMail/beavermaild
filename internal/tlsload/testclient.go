package tlsload

import (
	"crypto/tls"
	"net"
)

// DialTestClient connects with TLS to addr, skipping verify (tests only).
func DialTestClient(addr string) (net.Conn, error) {
	return tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
	})
}
