package tlsload_test

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/tlsload"
	"github.com/BeaverMail/beavermaild/internal/tlsload/tlstest"
)

// RFC 8314 4: logs carry the TLS version and cipher suite of the session.
func TestDescribe(t *testing.T) {
	sc, cc := net.Pipe()
	defer sc.Close()
	defer cc.Close()
	if got := tlsload.Describe(sc); got != "none" {
		t.Fatalf("plain conn: %q", got)
	}
	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"mx.example.net"})
	certs, err := tlsload.Load(certFile, keyFile, "1.3")
	if err != nil {
		t.Fatal(err)
	}
	server := certs.WrapServer(sc)
	go func() { _ = tls.Client(cc, &tls.Config{InsecureSkipVerify: true}).Handshake() }()
	if err := server.Handshake(); err != nil {
		t.Fatal(err)
	}
	if got := tlsload.Describe(server); !strings.HasPrefix(got, "TLS 1.3 TLS_") {
		t.Fatalf("tls conn: %q", got)
	}
}
