// Write-path and first-install API tests.
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/httpapi"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/security"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestSetupBootstrap(t *testing.T) {
	t.Parallel()
	srv, _ := newEmptyAPI(t)

	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/setup", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("setup status %d", res.Code)
	}
	var st struct {
		Needed bool `json:"needed"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &st); err != nil || !st.Needed {
		t.Fatalf("needed %+v err=%v", st, err)
	}

	body, _ := json.Marshal(map[string]string{"email": "root@mail.example.com", "password": "s3cret"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("setup %d %s", res.Code, res.Body.String())
	}
	var out struct {
		Token   string `json:"token"`
		Account struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"account"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Token == "" || out.Account.Email != "root@mail.example.com" || out.Account.Role != directory.RoleAdmin {
		t.Fatalf("out %+v", out)
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusConflict {
		t.Fatalf("second setup want 409 got %d %s", res.Code, res.Body.String())
	}
}

func TestDirectoryWrites(t *testing.T) {
	t.Parallel()
	srv, dir := newTestAPI(t)
	ctx := context.Background()
	tok := login(t, srv, "admin@api.test", "secret")

	// create domain
	body, _ := json.Marshal(map[string]any{"name": "new.example.com"})
	req := authedJSON(t, http.MethodPost, "/api/v1/domains", tok, body)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("create domain %d %s", res.Code, res.Body.String())
	}

	// create account
	body, _ = json.Marshal(map[string]any{"local_part": "bob", "password": "pw", "role": "user"})
	req = authedJSON(t, http.MethodPost, "/api/v1/domains/new.example.com/accounts", tok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("create account %d %s", res.Code, res.Body.String())
	}

	// patch role + active
	role := directory.RoleTenantAdmin
	active := false
	body, _ = json.Marshal(map[string]any{"role": role, "active": active})
	req = authedJSON(t, http.MethodPatch, "/api/v1/accounts/"+url.PathEscape("bob@new.example.com"), tok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("patch %d %s", res.Code, res.Body.String())
	}

	// set password then auth
	body, _ = json.Marshal(map[string]any{"password": "newer", "active": true})
	req = authedJSON(t, http.MethodPatch, "/api/v1/accounts/"+url.PathEscape("bob@new.example.com"), tok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("patch password %d %s", res.Code, res.Body.String())
	}
	if _, err := dir.Authenticate(ctx, "bob@new.example.com", "newer"); err != nil {
		t.Fatal(err)
	}

	// cannot delete self
	req = authedJSON(t, http.MethodDelete, "/api/v1/accounts/"+url.PathEscape("admin@api.test"), tok, nil)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("self delete want 403 got %d", res.Code)
	}

	// delete account
	req = authedJSON(t, http.MethodDelete, "/api/v1/accounts/"+url.PathEscape("bob@new.example.com"), tok, nil)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("delete account %d %s", res.Code, res.Body.String())
	}

	// delete domain with confirm
	body, _ = json.Marshal(map[string]string{"confirm": "new.example.com"})
	req = authedJSON(t, http.MethodDelete, "/api/v1/domains/new.example.com", tok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("delete domain %d %s", res.Code, res.Body.String())
	}
}

func TestTenantAdminCannotCreateAdminOrTouchOtherTenant(t *testing.T) {
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
	taTok := login(t, srv, "ta@other.test", "secret")

	body, _ := json.Marshal(map[string]any{"local_part": "x", "password": "pw", "role": directory.RoleAdmin})
	req := authedJSON(t, http.MethodPost, "/api/v1/domains/other.test/accounts", taTok, body)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("assign admin want 403 got %d %s", res.Code, res.Body.String())
	}

	body, _ = json.Marshal(map[string]any{"name": "hijack.test", "tenant_id": directory.DefaultTenantID})
	req = authedJSON(t, http.MethodPost, "/api/v1/domains", taTok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("create domain %d %s", res.Code, res.Body.String())
	}
	var created domainDTO
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.TenantID != 2 {
		t.Fatalf("tenant_admin forced own tenant, got %d", created.TenantID)
	}
}

func TestCookieMutationRequiresOrigin(t *testing.T) {
	t.Parallel()
	srv, _ := newTestAPI(t)
	tok := login(t, srv, "admin@api.test", "secret")

	body, _ := json.Marshal(map[string]any{"name": "csrf.example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domains", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "beaver_session", Value: tok})
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("cookie without origin want 403 got %d", res.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/domains", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	req.AddCookie(&http.Cookie{Name: "beaver_session", Value: tok})
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusCreated && res.Code != http.StatusOK {
		t.Fatalf("cookie with origin %d %s", res.Code, res.Body.String())
	}
}

func TestTenantAPIWrites(t *testing.T) {
	t.Parallel()
	srv, dir := newTestAPI(t)
	ctx := context.Background()
	adminTok := login(t, srv, "admin@api.test", "secret")

	body, _ := json.Marshal(map[string]string{"name": "Reseller"})
	req := authedJSON(t, http.MethodPost, "/api/v1/tenants", adminTok, body)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("create tenant %d %s", res.Code, res.Body.String())
	}
	var created struct {
		ID   uint32 `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil || created.ID == 0 || created.Name != "Reseller" {
		t.Fatalf("created %+v err=%v", created, err)
	}

	body, _ = json.Marshal(map[string]string{"name": "Reseller LLC"})
	req = authedJSON(t, http.MethodPatch, "/api/v1/tenants/"+itoa(created.ID), adminTok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("rename %d %s", res.Code, res.Body.String())
	}

	// default tenant cannot be deleted
	body, _ = json.Marshal(map[string]string{"confirm": "default"})
	req = authedJSON(t, http.MethodDelete, "/api/v1/tenants/1", adminTok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("delete default want 400 got %d %s", res.Code, res.Body.String())
	}

	other, err := dir.CreateDomain(ctx, created.ID, "reseller.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAccountRole(ctx, other.ID, "ta", "secret", directory.RoleTenantAdmin); err != nil {
		t.Fatal(err)
	}
	taTok := login(t, srv, "ta@reseller.test", "secret")

	body, _ = json.Marshal(map[string]string{"name": "Hack"})
	req = authedJSON(t, http.MethodPost, "/api/v1/tenants", taTok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("ta create want 403 got %d", res.Code)
	}

	body, _ = json.Marshal(map[string]string{"name": "Reseller Own"})
	req = authedJSON(t, http.MethodPatch, "/api/v1/tenants/"+itoa(created.ID), taTok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("ta rename own %d %s", res.Code, res.Body.String())
	}

	body, _ = json.Marshal(map[string]string{"name": "Nope"})
	req = authedJSON(t, http.MethodPatch, "/api/v1/tenants/1", taTok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("ta rename other want 403 got %d", res.Code)
	}

	body, _ = json.Marshal(map[string]string{"confirm": "Reseller Own"})
	req = authedJSON(t, http.MethodDelete, "/api/v1/tenants/"+itoa(created.ID), adminTok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("delete tenant %d %s", res.Code, res.Body.String())
	}
}

func TestListQueue(t *testing.T) {
	t.Parallel()
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
	if _, err := dir.CreateAccountRole(ctx, dom.ID, "user", "secret", directory.RoleUser); err != nil {
		t.Fatal(err)
	}
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	queue := mail.NewQueue(store, blobs)
	if _, err := queue.Enqueue(ctx, "sender@api.test", []string{"rcpt@example.com"}, []byte("Subject: hi\r\n\r\nbody")); err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(httpapi.Options{
		Listen:   "127.0.0.1:0",
		Dir:      dir,
		AuthKey:  "0123456789abcdef0123456789abcdef",
		AuthGate: security.NopGate{},
		Blobs:    blobs,
		Queue:    queue,
	})
	if err != nil {
		t.Fatal(err)
	}

	adminTok := login(t, srv, "admin@api.test", "secret")
	req := authedJSON(t, http.MethodGet, "/api/v1/queue", adminTok, nil)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("queue %d %s", res.Code, res.Body.String())
	}
	var out struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 {
		t.Fatalf("entries %v", out.Entries)
	}

	userTok := login(t, srv, "user@api.test", "secret")
	req = authedJSON(t, http.MethodGet, "/api/v1/queue", userTok, nil)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("user queue want 403 got %d", res.Code)
	}
}

func itoa(id uint32) string {
	return strconv.FormatUint(uint64(id), 10)
}

type domainDTO struct {
	ID       uint32 `json:"id"`
	Name     string `json:"name"`
	TenantID uint32 `json:"tenant_id"`
}

func newEmptyAPI(t *testing.T) (*httpapi.Server, *directory.Local) {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	srv, err := httpapi.New(httpapi.Options{
		Listen:   "127.0.0.1:0",
		Dir:      dir,
		AuthKey:  "0123456789abcdef0123456789abcdef",
		AuthGate: security.NopGate{},
		Blobs:    blobs,
		Queue:    mail.NewQueue(store, blobs),
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, dir
}

func authedJSON(t *testing.T, method, path, token string, body []byte) *http.Request {
	t.Helper()
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}
