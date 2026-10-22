// Long-lived API keys for integrations (bk_<id>_<secret>, SHA-256 of the secret at rest).
package directory

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BeaverMail/beaver/internal/storage"
)

// APIKeyPrefix marks Bearer values that are API keys rather than session tokens.
const APIKeyPrefix = "bk_"

// APIKeyDomain is the principal domain for API keys; .invalid (RFC 2606) never matches a hosted domain.
const APIKeyDomain = "api-key.invalid"

func apiKeyRecordKey(id uint32) []byte {
	return storage.AppendKey(nil, storage.SubspaceAccount, systemAccountID, id, colAPIKey, nil)
}

// CreateAPIKey stores a new key and returns it with the one-time plaintext token.
func (d *Local) CreateAPIKey(ctx context.Context, name, role string) (storage.APIKey, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		return storage.APIKey{}, "", fmt.Errorf("directory: api key name required (max 128 bytes)")
	}
	role = NormalizeRole(role)
	if role != RoleProvisioner {
		return storage.APIKey{}, "", fmt.Errorf("directory: api key role must be %s", RoleProvisioner)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return storage.APIKey{}, "", err
	}
	id, err := d.nextID(ctx, "apikey")
	if err != nil {
		return storage.APIKey{}, "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(secret)
	sum := sha256.Sum256([]byte(enc))
	key := storage.APIKey{ID: id, Name: name, Role: role, Hash: sum[:], Created: time.Now().Unix()}
	wire, err := storage.MarshalPersist(nil, 1, key)
	if err != nil {
		return storage.APIKey{}, "", err
	}
	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := batch.Set(storage.SubspaceAccount, storage.BatchSuffix(colAPIKey, id, nil), wire); err != nil {
		return storage.APIKey{}, "", err
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		return storage.APIKey{}, "", err
	}
	return key, APIKeyPrefix + strconv.FormatUint(uint64(id), 10) + "_" + enc, nil
}

// ListAPIKeys returns all keys sorted by id (hashes included; callers must not print them).
func (d *Local) ListAPIKeys(ctx context.Context) ([]storage.APIKey, error) {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceAccount, systemAccountID, 0, colAPIKey, 6)
	to := storage.AppendKey(nil, storage.SubspaceAccount, systemAccountID, ^uint32(0), colAPIKey, nil)
	var out []storage.APIKey
	err := d.store.Iterate(ctx, from, to, func(_, v []byte) error {
		var key storage.APIKey
		if err := storage.UnmarshalPersist(v, &key); err != nil {
			return err
		}
		out = append(out, key)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b storage.APIKey) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

// RevokeAPIKey deletes key id; ErrNotFound when it does not exist.
func (d *Local) RevokeAPIKey(ctx context.Context, id uint32) error {
	var key storage.APIKey
	if err := d.getRecord(ctx, apiKeyRecordKey(id), &key); err != nil {
		return err
	}
	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := batch.Delete(storage.SubspaceAccount, storage.BatchSuffix(colAPIKey, id, nil)); err != nil {
		return err
	}
	return d.store.Commit(ctx, batch)
}

// AuthenticateAPIKey resolves a bk_ token to a principal; any mismatch is ErrInvalidCredentials.
func (d *Local) AuthenticateAPIKey(ctx context.Context, token string) (Principal, error) {
	rest, ok := strings.CutPrefix(token, APIKeyPrefix)
	if !ok {
		return Principal{}, ErrInvalidCredentials
	}
	idStr, secret, ok := strings.Cut(rest, "_")
	if !ok || secret == "" {
		return Principal{}, ErrInvalidCredentials
	}
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil || id == 0 {
		return Principal{}, ErrInvalidCredentials
	}
	var key storage.APIKey
	if err := d.getRecord(ctx, apiKeyRecordKey(uint32(id)), &key); err != nil {
		if errors.Is(err, ErrNotFound) {
			return Principal{}, ErrInvalidCredentials
		}
		return Principal{}, err
	}
	sum := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(sum[:], key.Hash) != 1 {
		return Principal{}, ErrInvalidCredentials
	}
	return Principal{
		LocalPart:  "apikey-" + idStr,
		DomainName: APIKeyDomain,
		Role:       key.Role,
	}, nil
}
