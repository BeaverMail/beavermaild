package directory_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
)

func TestAPIKeyLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := openDir(t)

	if _, _, err := d.CreateAPIKey(ctx, "panel", directory.RoleAdmin); err == nil {
		t.Fatal("admin api key must be rejected")
	}
	if _, _, err := d.CreateAPIKey(ctx, " ", directory.RoleProvisioner); err == nil {
		t.Fatal("empty name must be rejected")
	}
	key, token, err := d.CreateAPIKey(ctx, "panel", directory.RoleProvisioner)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, directory.APIKeyPrefix) {
		t.Fatalf("token %q", token)
	}

	p, err := d.AuthenticateAPIKey(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if p.Role != directory.RoleProvisioner || p.DomainName != directory.APIKeyDomain || p.AccountID != 0 {
		t.Fatalf("principal %+v", p)
	}

	for _, bad := range []string{
		token + "x",
		token[:len(token)-1],
		"bk_999_" + token[strings.LastIndex(token, "_")+1:],
		"bk_",
		"bk_x_y",
		"bk_1",
	} {
		if _, err := d.AuthenticateAPIKey(ctx, bad); !errors.Is(err, directory.ErrInvalidCredentials) {
			t.Fatalf("token %q: err=%v", bad, err)
		}
	}

	keys, err := d.ListAPIKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].Name != "panel" {
		t.Fatalf("list %+v err=%v", keys, err)
	}
	if err := d.RevokeAPIKey(ctx, key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticateAPIKey(ctx, token); !errors.Is(err, directory.ErrInvalidCredentials) {
		t.Fatalf("revoked key err=%v", err)
	}
	if err := d.RevokeAPIKey(ctx, key.ID); !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("second revoke err=%v", err)
	}
}
