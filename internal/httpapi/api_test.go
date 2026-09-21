// HTTP API skeleton tests: health, login, role-scoped lists.
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/httpapi"
	"github.com/BeaverMail/beaver/internal/security"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestHealthAndLoginFlow(t *testing.T) {
	t.Parallel()
	srv, _ := newTestAPI(t)

	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("health %d", res.Code)
	}

	token := login(t, srv, "admin@api.test", "secret")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("me %d %s", res.Code, res.Body.String())
	}
	var me map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me["email"] != "admin@api.test" || me["role"] != directory.RoleAdmin {
		t.Fatalf("me %+v", me)
	}
}

func TestRoleScopedDomains(t *testing.T) {
	t.Parallel()
	srv, dir := newTestAPI(t)
	ctx := context.Background()

	other, err := dir.CreateDomain(ctx, 2, "other.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAccountRole(ctx, other.ID, "ta", "secret", directory.RoleTenantAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAccount(ctx, other.ID, "user", "secret"); err != nil {
		t.Fatal(err)
	}

	adminTok := login(t, srv, "admin@api.test", "secret")
	domains := listDomains(t, srv, adminTok)
	if len(domains) < 2 {
		t.Fatalf("admin domains %v", domains)
	}

	taTok := login(t, srv, "ta@other.test", "secret")
	domains = listDomains(t, srv, taTok)
	if len(domains) != 1 || domains[0]["name"] != "other.test" {
		t.Fatalf("tenant_admin domains %v", domains)
	}

	userTok := login(t, srv, "user@other.test", "secret")
	domains = listDomains(t, srv, userTok)
	if len(domains) != 1 || domains[0]["name"] != "other.test" {
		t.Fatalf("user domains %v", domains)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("user tenants want 403 got %d", res.Code)
	}
}

func TestNonLoopbackRequiresTLS(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	_, err = httpapi.New(httpapi.Options{
		Listen:  "0.0.0.0:8080",
		Dir:     dir,
		AuthKey: "0123456789abcdef0123456789abcdef",
	})
	if err == nil {
		t.Fatal("expected TLS required")
	}
}

func newTestAPI(t *testing.T) (*httpapi.Server, *directory.Local) {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	dom, _, err := dir.EnsureDomain(ctx, directory.DefaultTenantID, "api.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAccountRole(ctx, dom.ID, "admin", "secret", directory.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	srv, err := httpapi.New(httpapi.Options{
		Listen:   "127.0.0.1:0",
		Dir:      dir,
		AuthKey:  "0123456789abcdef0123456789abcdef",
		AuthGate: security.NopGate{},
		Blobs:    blobs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, dir
}

func login(t *testing.T, srv *httpapi.Server, email, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("login %s: %d %s", email, res.Code, res.Body.String())
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Token == "" {
		t.Fatal("empty token")
	}
	return out.Token
}

func listDomains(t *testing.T, srv *httpapi.Server, token string) []map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/domains", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("domains %d %s", res.Code, res.Body.String())
	}
	var out struct {
		Domains []map[string]any `json:"domains"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Domains
}
