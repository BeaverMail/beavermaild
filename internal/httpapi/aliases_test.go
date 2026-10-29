package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
)

func TestAliasAPI(t *testing.T) {
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
	if _, err := dir.CreateAccountRole(ctx, dom.ID, "alice", "pw", directory.RoleUser); err != nil {
		t.Fatal(err)
	}
	bossTok := login(t, srv, "boss@customer.example", "pw")
	call := func(tok, method, path, body string) int {
		var b []byte
		if body != "" {
			b = []byte(body)
		}
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, authedJSON(t, method, path, tok, b))
		return res.Code
	}

	if code := call(bossTok, http.MethodPost, "/api/v1/domains/customer.example/aliases",
		`{"local_part":"info","targets":["alice@customer.example","boss@customer.example"]}`); code != http.StatusCreated {
		t.Fatalf("create %d", code)
	}
	if code := call(bossTok, http.MethodPost, "/api/v1/domains/customer.example/aliases",
		`{"local_part":"alice","targets":["boss@customer.example"]}`); code != http.StatusConflict {
		t.Fatalf("alias over mailbox want 409 got %d", code)
	}
	if code := call(bossTok, http.MethodPost, "/api/v1/domains/customer.example/aliases",
		`{"local_part":"x","targets":["admin@api.test"]}`); code != http.StatusBadRequest {
		t.Fatalf("cross-tenant target want 400 got %d", code)
	}
	if code := call(bossTok, http.MethodGet, "/api/v1/domains/api.test/aliases", ""); code != http.StatusForbidden {
		t.Fatalf("other tenant list want 403 got %d", code)
	}
	if code := call(login(t, srv, "alice@customer.example", "pw"), http.MethodGet, "/api/v1/domains/customer.example/aliases", ""); code != http.StatusForbidden {
		t.Fatalf("user list want 403 got %d", code)
	}
	if code := call(bossTok, http.MethodPatch, "/api/v1/aliases/info@customer.example", `{"targets":["alice@customer.example"]}`); code != http.StatusOK {
		t.Fatalf("patch %d", code)
	}
	if code := call(bossTok, http.MethodDelete, "/api/v1/aliases/info@customer.example", ""); code != http.StatusOK {
		t.Fatalf("delete %d", code)
	}
	if code := call(bossTok, http.MethodDelete, "/api/v1/aliases/info@customer.example", ""); code != http.StatusNotFound {
		t.Fatalf("second delete want 404 got %d", code)
	}
}
