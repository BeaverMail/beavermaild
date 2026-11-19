package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/httpapi"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/security"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// The account list reports per-mailbox usage so admins can see who fills the domain quota.
func TestListAccountsIncludesUsage(t *testing.T) {
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
	acc, err := dir.CreateAccountRole(ctx, dom.ID, "admin", "secret", directory.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	inbox := mail.NewInbox(store, blobs)
	raw := []byte("Subject: usage\r\n\r\nhello\r\n")
	if _, err := inbox.Deliver(ctx, acc.ID, raw); err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(httpapi.Options{
		Listen: "127.0.0.1:0", Dir: dir, AuthKey: "0123456789abcdef0123456789abcdef",
		AuthGate: security.NopGate{}, Blobs: blobs, Inbox: inbox,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/domains/api.test/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+login(t, srv, "admin@api.test", "secret"))
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("list %d %s", res.Code, res.Body.String())
	}
	var out struct {
		Accounts []struct {
			Email        string `json:"email"`
			StorageUsed  uint64 `json:"storage_used"`
			MessagesUsed uint32 `json:"messages_used"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Accounts) != 1 || out.Accounts[0].StorageUsed != uint64(len(raw)) || out.Accounts[0].MessagesUsed != 1 {
		t.Fatalf("accounts %+v", out.Accounts)
	}
}

// PATCH sets per-mailbox limits that delivery enforces; omitted limits keep their value.
func TestPatchAccountQuotaLimits(t *testing.T) {
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
	bob, err := dir.CreateAccountRole(ctx, dom.ID, "bob", "pw", directory.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	inbox := mail.NewInbox(store, blobs)
	inbox.SetQuotaDefaults(mail.QuotaDefaults{StorageBytes: 1 << 30, Messages: 1000})
	srv, err := httpapi.New(httpapi.Options{
		Listen: "127.0.0.1:0", Dir: dir, AuthKey: "0123456789abcdef0123456789abcdef",
		AuthGate: security.NopGate{}, Blobs: blobs, Inbox: inbox,
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := login(t, srv, "admin@api.test", "secret")

	type quotaOut struct {
		StorageLimit     uint64 `json:"storage_limit"`
		MessagesLimit    uint32 `json:"messages_limit"`
		StorageLimitSet  bool   `json:"storage_limit_set"`
		MessagesLimitSet bool   `json:"messages_limit_set"`
	}
	patch := func(body string) quotaOut {
		t.Helper()
		req := authedJSON(t, http.MethodPatch, "/api/v1/accounts/bob@api.test", tok, []byte(body))
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("patch %s: %d %s", body, res.Code, res.Body.String())
		}
		var out quotaOut
		if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if got := patch(`{"storage_limit":40,"messages_limit":5}`); got != (quotaOut{40, 5, true, true}) {
		t.Fatalf("set both: %+v", got)
	}
	if got := patch(`{"messages_limit":0}`); got != (quotaOut{40, 0, true, true}) {
		t.Fatalf("partial update must keep storage_limit: %+v", got)
	}
	// messages_limit_default drops the account's own limit: the server default applies again.
	if got := patch(`{"messages_limit_default":true}`); got != (quotaOut{40, 1000, true, false}) {
		t.Fatalf("back to default: %+v", got)
	}
	req := authedJSON(t, http.MethodPatch, "/api/v1/accounts/bob@api.test", tok, []byte(`{"storage_limit":1,"storage_limit_default":true}`))
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("limit and default together: %d", res.Code)
	}
	if _, err := inbox.Deliver(ctx, bob.ID, []byte("Subject: a\r\n\r\nshort\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, bob.ID, []byte("Subject: b\r\n\r\nthis body pushes the mailbox over forty bytes\r\n")); err != mail.ErrOverQuota {
		t.Fatalf("deliver over limit err=%v", err)
	}
}

// GET /defaults reports the server-wide quota and send rate to those who manage domains, not to users.
func TestServerDefaults(t *testing.T) {
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
	for _, a := range [][2]string{{"admin", directory.RoleAdmin}, {"bob", directory.RoleUser}} {
		if _, err := dir.CreateAccountRole(ctx, dom.ID, a[0], "secret", a[1]); err != nil {
			t.Fatal(err)
		}
	}
	blobs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	inbox := mail.NewInbox(store, blobs)
	inbox.SetQuotaDefaults(mail.QuotaDefaults{StorageBytes: 1 << 30, Messages: 1000})
	srv, err := httpapi.New(httpapi.Options{
		Listen: "127.0.0.1:0", Dir: dir, AuthKey: "0123456789abcdef0123456789abcdef",
		AuthGate: security.NopGate{}, Blobs: blobs, Inbox: inbox,
		SendLimit: security.SendLimitConfig{MaxMessages: 100, Window: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	get := func(email string) *httptest.ResponseRecorder {
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, authedJSON(t, http.MethodGet, "/api/v1/defaults", login(t, srv, email, "secret"), nil))
		return res
	}
	res := get("admin@api.test")
	if want := `{"storage_bytes":1073741824,"messages":1000,"send_max_messages":100,"send_window":"1h"}`; res.Code != http.StatusOK || strings.TrimSpace(res.Body.String()) != want {
		t.Fatalf("admin: %d %s, want %s", res.Code, res.Body.String(), want)
	}
	if res := get("bob@api.test"); res.Code != http.StatusForbidden {
		t.Fatalf("user: %d", res.Code)
	}
}
