package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/httpapi"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/security"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

// A provisioner key manages tenants, domains, and accounts, cannot reach instance ops or mint
// admins, and keeps working while the shared login limiter has locked out its IP.
func TestProvisionerAPIKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	gate := security.NewRateLimitGate(security.RateLimitConfig{MaxAttempts: 1, Window: time.Hour})
	srv, err := httpapi.New(httpapi.Options{
		Listen: "127.0.0.1:0", Dir: dir, AuthKey: "0123456789abcdef0123456789abcdef",
		AuthGate: gate, Blobs: blobs, Queue: mail.NewQueue(store, blobs),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := dir.CreateAPIKey(ctx, "panel", directory.RoleProvisioner)
	if err != nil {
		t.Fatal(err)
	}

	// Lock out the test client IP (httptest uses 192.0.2.1) through a failed login.
	gate.RecordAuthFailure("192.0.2.1", "")
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, authedJSON(t, http.MethodPost, "/api/v1/auth/login", "",
		[]byte(`{"email":"x@example.com","password":"y"}`)))
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("login want 429 got %d", res.Code)
	}

	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var b []byte
		if body != "" {
			b = []byte(body)
		}
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, authedJSON(t, method, path, token, b))
		return res
	}

	res = call(http.MethodPost, "/api/v1/tenants", `{"name":"Customer"}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("create tenant %d %s", res.Code, res.Body.String())
	}
	var tenant struct {
		ID uint32 `json:"id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &tenant); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"name": "customer.example", "tenant_id": tenant.ID, "mail_hostname": "mail.customer.example"})
	if res := call(http.MethodPost, "/api/v1/domains", string(body)); res.Code != http.StatusCreated {
		t.Fatalf("create domain %d %s", res.Code, res.Body.String())
	}
	if res := call(http.MethodPost, "/api/v1/domains/customer.example/accounts", `{"local_part":"alice","password":"pw"}`); res.Code != http.StatusCreated {
		t.Fatalf("create account %d %s", res.Code, res.Body.String())
	}
	if res := call(http.MethodPost, "/api/v1/domains/customer.example/accounts", `{"local_part":"root","password":"pw","role":"admin"}`); res.Code != http.StatusForbidden {
		t.Fatalf("create admin want 403 got %d", res.Code)
	}
	if res := call(http.MethodPatch, "/api/v1/accounts/alice@customer.example", `{"role":"admin"}`); res.Code != http.StatusForbidden {
		t.Fatalf("promote to admin want 403 got %d", res.Code)
	}
	if res := call(http.MethodGet, "/api/v1/tenants", ""); res.Code != http.StatusOK {
		t.Fatalf("list tenants %d", res.Code)
	}
	for _, path := range []string{"/api/v1/queue", "/api/v1/status", "/api/v1/logs", "/api/v1/delivery"} {
		if res := call(http.MethodGet, path, ""); res.Code != http.StatusForbidden {
			t.Fatalf("%s want 403 got %d", path, res.Code)
		}
	}

	// A wrong key is 401 and does not depend on the limiter.
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, authedJSON(t, http.MethodGet, "/api/v1/me", token+"x", nil))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("bad key want 401 got %d", res.Code)
	}
}
