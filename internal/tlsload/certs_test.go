package tlsload_test

import (
	"crypto/tls"
	"errors"
	"testing"

	"github.com/BeaverMail/beaver/internal/tlsload"
	"github.com/BeaverMail/beaver/internal/tlsload/tlstest"
)

func TestLoadAndTLSListen(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := tlstest.WritePEM(t, dir, []string{"localhost"})

	certs, err := tlsload.Load(certFile, keyFile, "1.2")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := certs.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 2)
	go func() {
		conn, err := tlsload.DialTestClient(ln.Addr().String())
		if conn != nil {
			_ = conn.Close()
		}
		errCh <- err
	}()
	go func() {
		srv, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer srv.Close()
		tc, ok := srv.(*tls.Conn)
		if !ok {
			errCh <- errors.New("accept: not *tls.Conn")
			return
		}
		errCh <- tc.Handshake()
	}()
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}
