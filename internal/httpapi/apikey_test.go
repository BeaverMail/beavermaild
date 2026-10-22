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

// A retried tenant create with the same external_id is 409 and returns the existing tenant.
func TestCreateTenantExternalIDIdempotent(t *testing.T) {
	t.Parallel()
	srv, _ := newTestAPI(t)
	tok := login(t, srv, "admin@api.test", "secret")
	type tenantOut struct {
		ID         uint32 `json:"id"`
		ExternalID string `json:"external_id"`
	}
	create := func() *httptest.ResponseRecorder {
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, authedJSON(t, http.MethodPost, "/api/v1/tenants", tok,
			[]byte(`{"name":"Customer","external_id":"cust-42"}`)))
		return res
	}
	res := create()
	if res.Code != http.StatusCreated {
		t.Fatalf("create %d %s", res.Code, res.Body.String())
	}
	var first tenantOut
	if err := json.Unmarshal(res.Body.Bytes(), &first); err != nil || first.ExternalID != "cust-42" {
		t.Fatalf("create body %s err=%v", res.Body.String(), err)
	}
	res = create()
	if res.Code != http.StatusConflict {
		t.Fatalf("repeat want 409 got %d", res.Code)
	}
	var conflict struct {
		Error  string    `json:"error"`
		Tenant tenantOut `json:"tenant"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &conflict); err != nil || conflict.Tenant.ID != first.ID {
		t.Fatalf("conflict body %s err=%v", res.Body.String(), err)
	}
}

// Only admin/provisioner set the tenant cap; tenants report summed mailbox usage.
func TestTenantStorageLimitAPI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	root, _, err := dir.EnsureDomain(ctx, directory.DefaultTenantID, "api.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAccountRole(ctx, root.ID, "admin", "secret", directory.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	tenant, err := dir.CreateTenant(ctx, "Customer", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	dom, _, err := dir.EnsureDomain(ctx, tenant.ID, "customer.example")
	if err != nil {
		t.Fatal(err)
	}
	boss, err := dir.CreateAccountRole(ctx, dom.ID, "boss", "pw", directory.RoleTenantAdmin)
	if err != nil {
		t.Fatal(err)
	}
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	inbox := mail.NewInbox(store, blobs)
	raw := []byte("Subject: usage\r\n\r\nhello\r\n")
	if _, err := inbox.Deliver(ctx, boss.ID, raw); err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(httpapi.Options{
		Listen: "127.0.0.1:0", Dir: dir, AuthKey: "0123456789abcdef0123456789abcdef",
		AuthGate: security.NopGate{}, Blobs: blobs, Inbox: inbox,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/tenants/" + itoa(tenant.ID)
	patch := func(tok, body string) int {
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, authedJSON(t, http.MethodPatch, path, tok, []byte(body)))
		return res.Code
	}
	bossTok := login(t, srv, "boss@customer.example", "pw")
	if code := patch(bossTok, `{"storage_limit":999999}`); code != http.StatusForbidden {
		t.Fatalf("tenant_admin raising cap want 403 got %d", code)
	}
	if code := patch(bossTok, `{"name":"Renamed"}`); code != http.StatusOK {
		t.Fatalf("tenant_admin rename want 200 got %d", code)
	}
	if code := patch(login(t, srv, "admin@api.test", "secret"), `{"storage_limit":1000}`); code != http.StatusOK {
		t.Fatalf("admin set cap want 200 got %d", code)
	}

	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, authedJSON(t, http.MethodGet, "/api/v1/tenants", bossTok, nil))
	var out struct {
		Tenants []struct {
			Name         string `json:"name"`
			StorageLimit uint64 `json:"storage_limit"`
			StorageUsed  uint64 `json:"storage_used"`
		} `json:"tenants"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tenants) != 1 || out.Tenants[0].Name != "Renamed" || out.Tenants[0].StorageLimit != 1000 ||
		out.Tenants[0].StorageUsed != uint64(len(raw)) {
		t.Fatalf("tenants %+v", out.Tenants)
	}
}

// Only admin/provisioner suspend login; nobody suspends their own domain; suspended users get 401.
func TestLoginDisabledAPI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, dir := newTestAPI(t)
	tenant, err := dir.CreateTenant(ctx, "Customer", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	dom, _, err := dir.EnsureDomain(ctx, tenant.ID, "customer.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAccountRole(ctx, dom.ID, "boss", "pw", directory.RoleTenantAdmin); err != nil {
		t.Fatal(err)
	}
	adminTok := login(t, srv, "admin@api.test", "secret")
	bossTok := login(t, srv, "boss@customer.example", "pw")
	patch := func(tok, path, body string) int {
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, authedJSON(t, http.MethodPatch, path, tok, []byte(body)))
		return res.Code
	}
	tenantPath := "/api/v1/tenants/" + itoa(tenant.ID)

	if code := patch(bossTok, "/api/v1/domains/customer.example", `{"login_disabled":false}`); code != http.StatusForbidden {
		t.Fatalf("tenant_admin on domain want 403 got %d", code)
	}
	if code := patch(bossTok, tenantPath, `{"login_disabled":false}`); code != http.StatusForbidden {
		t.Fatalf("tenant_admin on tenant want 403 got %d", code)
	}
	if code := patch(adminTok, "/api/v1/domains/api.test", `{"login_disabled":true}`); code != http.StatusForbidden {
		t.Fatalf("own domain want 403 got %d", code)
	}
	if code := patch(adminTok, tenantPath, `{"login_disabled":true}`); code != http.StatusOK {
		t.Fatalf("admin suspend tenant want 200 got %d", code)
	}

	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, authedJSON(t, http.MethodPost, "/api/v1/auth/login", "",
		[]byte(`{"email":"boss@customer.example","password":"pw"}`)))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("suspended login want 401 got %d", res.Code)
	}
}

// Suspended users retrying with the right password must not trip the shared IP limiter.
func TestLoginDisabledDoesNotTripRateLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	if _, err := dir.BootstrapAdmin(ctx, "root@example.com", "secret"); err != nil {
		t.Fatal(err)
	}
	tenant, err := dir.CreateTenant(ctx, "Customer", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	dom, _, err := dir.EnsureDomain(ctx, tenant.ID, "customer.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAccountRole(ctx, dom.ID, "alice", "pw", directory.RoleUser); err != nil {
		t.Fatal(err)
	}
	if err := dir.SetTenantLoginDisabled(ctx, tenant.ID, true); err != nil {
		t.Fatal(err)
	}
	gate := security.NewRateLimitGate(security.RateLimitConfig{MaxAttempts: 2, Window: time.Hour})
	srv, err := httpapi.New(httpapi.Options{
		Listen: "127.0.0.1:0", Dir: dir, AuthKey: "0123456789abcdef0123456789abcdef", AuthGate: gate,
	})
	if err != nil {
		t.Fatal(err)
	}
	loginCode := func(email, pw string) int {
		res := httptest.NewRecorder()
		body, _ := json.Marshal(map[string]string{"email": email, "password": pw})
		srv.Handler().ServeHTTP(res, authedJSON(t, http.MethodPost, "/api/v1/auth/login", "", body))
		return res.Code
	}
	for range 5 {
		if code := loginCode("alice@customer.example", "pw"); code != http.StatusUnauthorized {
			t.Fatalf("suspended login want 401 got %d", code)
		}
	}
	if code := loginCode("root@example.com", "secret"); code != http.StatusOK {
		t.Fatalf("other user after suspended retries want 200 got %d", code)
	}
}
