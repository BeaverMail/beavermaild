// Cleartext listener tests: HTTPS redirect and TLS prerequisite.
package httpapi_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/httpapi"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
	"github.com/BeaverMail/beaver/internal/tlsload"
)

func newPlainAPI(t *testing.T, listen string, certs *tlsload.Certs) (*httpapi.Server, error) {
	t.Helper()
	store, err := sqlite.Open(context.Background(), "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return httpapi.New(httpapi.Options{
		Listen:      listen,
		PlainListen: ":80",
		Dir:         directory.NewLocal(store),
		AuthKey:     "0123456789abcdef0123456789abcdef",
		Certs:       certs,
	})
}

func TestPlainListenRequiresTLS(t *testing.T) {
	t.Parallel()
	if _, err := newPlainAPI(t, "127.0.0.1:8080", nil); err == nil {
		t.Fatal("expected error: plain_listen without TLS listen")
	}
}

func TestPlainHandlerRedirectsToHTTPS(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ listen, want string }{
		{":443", "https://mail.example.com/api/v1/me?x=1"},
		{":8443", "https://mail.example.com:8443/api/v1/me?x=1"},
	} {
		srv, err := newPlainAPI(t, tc.listen, tlsload.FromConfig(&tls.Config{}))
		if err != nil {
			t.Fatal(err)
		}
		res := httptest.NewRecorder()
		srv.PlainHandler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "http://mail.example.com:80/api/v1/me?x=1", nil))
		if res.Code != http.StatusMovedPermanently || res.Header().Get("Location") != tc.want {
			t.Fatalf("listen %s: %d %q want %q", tc.listen, res.Code, res.Header().Get("Location"), tc.want)
		}
	}
}
