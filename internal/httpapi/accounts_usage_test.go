package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/httpapi"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/security"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
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
		StorageLimit  uint64 `json:"storage_limit"`
		MessagesLimit uint32 `json:"messages_limit"`
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

	if got := patch(`{"storage_limit":40,"messages_limit":5}`); got != (quotaOut{40, 5}) {
		t.Fatalf("set both: %+v", got)
	}
	if got := patch(`{"messages_limit":0}`); got != (quotaOut{40, 0}) {
		t.Fatalf("partial update must keep storage_limit: %+v", got)
	}
	if _, err := inbox.Deliver(ctx, bob.ID, []byte("Subject: a\r\n\r\nshort\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, bob.ID, []byte("Subject: b\r\n\r\nthis body pushes the mailbox over forty bytes\r\n")); err != mail.ErrOverQuota {
		t.Fatalf("deliver over limit err=%v", err)
	}
}
