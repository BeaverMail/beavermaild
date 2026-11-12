package directory

import (
	"context"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// Every failed login pays one bcrypt comparison, whether the account exists or not: answering
// unknown users without one made them ~40 ms faster, which tells an attacker which addresses are
// real (user enumeration by timing).
func TestAuthenticateUnknownUserCostsAHash(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d := NewLocal(store)
	dom, _, err := d.EnsureDomain(ctx, DefaultTenantID, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccount(ctx, dom.ID, "alice", "secret"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	verifyPassword = func(hash []byte, password string) error { calls++; return VerifyPassword(hash, password) }
	t.Cleanup(func() { verifyPassword = VerifyPassword })
	for _, email := range []string{"alice@example.org", "nobody@example.org", "alice@unknown.example", "not-an-address"} {
		calls = 0
		if _, err := d.Authenticate(ctx, email, "wrong"); err == nil {
			t.Fatalf("%s: login succeeded", email)
		}
		if calls != 1 {
			t.Errorf("%s: %d password comparisons, want 1 like any failed login", email, calls)
		}
	}
}
