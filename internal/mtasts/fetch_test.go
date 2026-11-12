package mtasts

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/security"
)

// SSRF: mta-sts.<domain> is named by the recipient domain's DNS; a policy host on an internal address
// is never contacted (the default resolver runs with allowPrivate=false).
func TestPolicyFetchRefusesInternalAddresses(t *testing.T) {
	t.Parallel()
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	t.Cleanup(srv.Close)
	_, err := fetchPolicy(context.Background(), policyClient(false), srv.URL+policyPath)
	if !errors.Is(err, security.ErrPrivateAddr) || hit {
		t.Fatalf("err %v, server hit %v; want refused before connecting", err, hit)
	}
}

// RFC 8461 3.3: "HTTP 3xx redirects MUST NOT be followed".
func TestPolicyFetchDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	followed := false
	mux := http.NewServeMux()
	mux.HandleFunc(policyPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		followed = true
		_, _ = w.Write([]byte("version: STSv1\nmode: enforce\nmx: mx.example.org\nmax_age: 86400\n"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	_, err := fetchPolicy(context.Background(), policyClient(true), srv.URL+policyPath)
	if err == nil || !strings.Contains(err.Error(), "status 302") || followed {
		t.Fatalf("err %v, followed %v; want the 302 rejected", err, followed)
	}
}
