// Write-path and first-install API tests.
package httpapi_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/httpapi"
	beaverlog "github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/security"
	"github.com/BeaverMail/beaver/internal/servicestatus"
	"github.com/BeaverMail/beaver/internal/smtp"
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

func TestCreateDomainHostingFields(t *testing.T) {
	t.Parallel()
	srv, dir := newTestAPI(t)
	dataDir := t.TempDir()
	dir.SetDataDir(dataDir)
	tok := login(t, srv, "admin@api.test", "secret")

	body, _ := json.Marshal(map[string]any{
		"name":              "hosted.example.com",
		"mail_hostname":     "mail.hosted.example.com",
		"ssl_mode":          "acme",
		"dkim_enabled":      true,
		"antispam":          true,
		"send_max_messages": 25,
		"send_window":       "1h",
		"storage_bytes":     2048,
		"messages_quota":    10,
	})
	req := authedJSON(t, http.MethodPost, "/api/v1/domains", tok, body)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("create %d %s", res.Code, res.Body.String())
	}
	var created domainDTO
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !created.DKIMEnabled || !created.AntiSpam || created.SSLMode != "acme" {
		t.Fatalf("created %+v", created)
	}
	if !created.DKIMActive || !created.SSLActive || !created.AntiSpamActive {
		t.Fatalf("badges %+v", created)
	}
	if created.AccountCount != 0 {
		t.Fatalf("account_count %d", created.AccountCount)
	}

	getReq := authedJSON(t, http.MethodGet, "/api/v1/domains/hosted.example.com", tok, nil)
	getRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("get %d %s", getRes.Code, getRes.Body.String())
	}

	patchBody, _ := json.Marshal(map[string]any{
		"mail_hostname": "mail2.hosted.example.com",
		"ssl_mode":      "acme",
		"dkim_enabled":  true,
		"antispam":      false,
		"catch_all":     "abuse",
	})
	patchReq := authedJSON(t, http.MethodPatch, "/api/v1/domains/hosted.example.com", tok, patchBody)
	patchRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(patchRes, patchReq)
	if patchRes.Code != http.StatusOK {
		t.Fatalf("patch %d %s", patchRes.Code, patchRes.Body.String())
	}
	var patched domainDTO
	if err := json.Unmarshal(patchRes.Body.Bytes(), &patched); err != nil {
		t.Fatal(err)
	}
	if patched.AntiSpam || patched.AntiSpamActive {
		t.Fatalf("antispam should be off: %+v", patched)
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
	id, err := queue.Enqueue(ctx, "sender@api.test", []string{"rcpt@example.com"}, []byte("Subject: hi\r\n\r\nbody"))
	if err != nil {
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

	// hold → retry → cancel
	req = authedJSON(t, http.MethodPost, "/api/v1/queue/"+itoa(id)+"/hold", adminTok, nil)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("hold %d %s", res.Code, res.Body.String())
	}
	req = authedJSON(t, http.MethodGet, "/api/v1/queue", adminTok, nil)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if held, _ := out.Entries[0]["held"].(bool); !held {
		t.Fatalf("want held after hold: %v", out.Entries[0])
	}

	req = authedJSON(t, http.MethodPost, "/api/v1/queue/"+itoa(id)+"/retry", adminTok, nil)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("retry %d %s", res.Code, res.Body.String())
	}

	req = authedJSON(t, http.MethodDelete, "/api/v1/queue/"+itoa(id), adminTok, nil)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("cancel %d %s", res.Code, res.Body.String())
	}
	req = authedJSON(t, http.MethodGet, "/api/v1/queue", adminTok, nil)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 0 {
		t.Fatalf("after cancel entries %v", out.Entries)
	}
}

func TestDeliveryTestRelay(t *testing.T) {
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

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go serveProbeMock(ln)

	remote := smtp.RemoteConfig{Relay: ln.Addr().String()}
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	srv, err := httpapi.New(httpapi.Options{
		Listen:   "127.0.0.1:0",
		Dir:      dir,
		AuthKey:  "0123456789abcdef0123456789abcdef",
		AuthGate: security.NopGate{},
		Blobs:    blobs,
		Queue:    mail.NewQueue(store, blobs),
		Remote:   &remote,
	})
	if err != nil {
		t.Fatal(err)
	}

	adminTok := login(t, srv, "admin@api.test", "secret")
	body, _ := json.Marshal(map[string]string{"mode": "relay"})
	req := authedJSON(t, http.MethodPost, "/api/v1/delivery/test", adminTok, body)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("delivery test %d %s", res.Code, res.Body.String())
	}
	var out struct {
		OK   bool   `json:"ok"`
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.Mode != "relay" {
		t.Fatalf("%+v", out)
	}

	userTok := login(t, srv, "user@api.test", "secret")
	req = authedJSON(t, http.MethodPost, "/api/v1/delivery/test", userTok, body)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("user want 403 got %d", res.Code)
	}

	req = authedJSON(t, http.MethodGet, "/api/v1/delivery", adminTok, nil)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("delivery status %d %s", res.Code, res.Body.String())
	}
	var st struct {
		RelayConfigured bool   `json:"relay_configured"`
		Relay           string `json:"relay"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.RelayConfigured || st.Relay != ln.Addr().String() {
		t.Fatalf("status %+v", st)
	}
}

func serveProbeMock(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(c)
			_, _ = fmt.Fprint(c, "220 probe ESMTP\r\n")
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(line, "EHLO"):
					_, _ = fmt.Fprint(c, "250-probe\r\n250 OK\r\n")
				case strings.HasPrefix(line, "QUIT"):
					_, _ = fmt.Fprint(c, "221 bye\r\n")
					return
				}
			}
		}(conn)
	}
}

func itoa(id uint32) string {
	return strconv.FormatUint(uint64(id), 10)
}

type domainDTO struct {
	ID             uint32 `json:"id"`
	Name           string `json:"name"`
	TenantID       uint32 `json:"tenant_id"`
	AccountCount   int    `json:"account_count"`
	StorageUsed    uint64 `json:"storage_used"`
	SSLActive      bool   `json:"ssl_active"`
	DKIMActive     bool   `json:"dkim_active"`
	AntiSpamActive bool   `json:"antispam_active"`
	DKIMEnabled    bool   `json:"dkim_enabled"`
	SSLMode        string `json:"ssl_mode"`
	AntiSpam       bool   `json:"antispam"`
}

func TestServicesStatus(t *testing.T) {
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

	reg := servicestatus.New()
	reg.Set(servicestatus.Entry{
		ID:     "smtp_inbound",
		Name:   "SMTP inbound",
		Listen: "127.0.0.1:2525",
		State:  servicestatus.StateUp,
	})
	reg.Set(servicestatus.Entry{
		ID:     "imap",
		Name:   "IMAP",
		Listen: ":143",
		State:  servicestatus.StateError,
		Error:  "address already in use",
	})

	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	srv, err := httpapi.New(httpapi.Options{
		Listen:   "127.0.0.1:0",
		Dir:      dir,
		AuthKey:  "0123456789abcdef0123456789abcdef",
		AuthGate: security.NopGate{},
		Blobs:    blobs,
		Queue:    mail.NewQueue(store, blobs),
		Status:   reg,
	})
	if err != nil {
		t.Fatal(err)
	}

	adminTok := login(t, srv, "admin@api.test", "secret")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status %d %s", res.Code, res.Body.String())
	}
	var out struct {
		Services []struct {
			ID     string `json:"id"`
			State  string `json:"state"`
			Listen string `json:"listen"`
			Error  string `json:"error"`
		} `json:"services"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Services) != 2 {
		t.Fatalf("services %+v", out.Services)
	}
	if out.Services[0].ID != "imap" || out.Services[0].State != servicestatus.StateError {
		t.Fatalf("want imap error first (sorted): %+v", out.Services[0])
	}
	if out.Services[1].ID != "smtp_inbound" || out.Services[1].Listen == "" {
		t.Fatalf("smtp: %+v", out.Services[1])
	}

	userTok := login(t, srv, "user@api.test", "secret")
	req = httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("user want 403 got %d", res.Code)
	}
}

func TestLogs(t *testing.T) {
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

	path := filepath.Join(t.TempDir(), "beaver.log")
	rf, err := beaverlog.OpenFile(path, beaverlog.FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rf.Close() })
	var discard bytes.Buffer
	logger := beaverlog.WithFile(slog.New(slog.NewTextHandler(&discard, nil)), rf)
	logger.Info("older", "n", 1)
	time.Sleep(2 * time.Millisecond)
	logger.Info("smtp listening", "addr", "127.0.0.1:25")
	_ = rf.Close()

	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	srv, err := httpapi.New(httpapi.Options{
		Listen:   "127.0.0.1:0",
		Dir:      dir,
		AuthKey:  "0123456789abcdef0123456789abcdef",
		AuthGate: security.NopGate{},
		Blobs:    blobs,
		Queue:    mail.NewQueue(store, blobs),
		LogFile:  path,
	})
	if err != nil {
		t.Fatal(err)
	}

	adminTok := login(t, srv, "admin@api.test", "secret")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/logs?q=smtp&limit=50", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("logs %d %s", res.Code, res.Body.String())
	}
	var out struct {
		Entries []struct {
			Msg  string    `json:"msg"`
			Time time.Time `json:"time"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 || out.Entries[0].Msg != "smtp listening" {
		t.Fatalf("%+v", out.Entries)
	}

	before := out.Entries[0].Time.Format(time.RFC3339Nano)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/logs?before="+url.QueryEscape(before)+"&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("before %d %s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 || out.Entries[0].Msg != "older" {
		t.Fatalf("before page: %+v", out.Entries)
	}

	userTok := login(t, srv, "user@api.test", "secret")
	req = httptest.NewRequest(http.MethodGet, "/api/v1/logs", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("user want 403 got %d", res.Code)
	}
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
