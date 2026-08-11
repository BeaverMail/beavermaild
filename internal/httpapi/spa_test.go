package httpapi_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/httpapi"
	"github.com/BeaverMail/beaver/internal/security"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestSPAServesIndexAndAPI(t *testing.T) {
	t.Parallel()
	ui := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>ui</html>")},
		"robots.txt": &fstest.MapFile{Data: []byte("User-agent: *\n")},
	}
	srv := newAPIWithUI(t, ui)

	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/", nil))
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "ui") {
		t.Fatalf("index %d %q", res.Code, res.Body.String())
	}

	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/domains/example.com", nil))
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "ui") {
		t.Fatalf("spa fallback %d %q", res.Code, res.Body.String())
	}

	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "ok") {
		t.Fatalf("health %d %q", res.Code, res.Body.String())
	}
}

func newAPIWithUI(t *testing.T, ui fs.FS) *httpapi.Server {
	t.Helper()
	ctx := t.Context()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv, err := httpapi.New(httpapi.Options{
		Listen:   "127.0.0.1:0",
		Dir:      directory.NewLocal(store),
		AuthKey:  "0123456789abcdef0123456789abcdef",
		AuthGate: security.NopGate{},
		UI:       ui,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}
