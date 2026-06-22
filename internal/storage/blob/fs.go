// Package blob stores large payloads on the filesystem (content-addressed Blake3).
package blob

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/zeebo/blake3"
)

// InlineThreshold is the max payload size kept in KV instead of blob fs.
const InlineThreshold = 64 << 10 // 64 KiB

// ErrNotFound is returned when a blob hash has no file on disk.
var ErrNotFound = errors.New("blob: not found")

// FS is a content-addressed blob directory (hash-prefix paths).
type FS struct {
	root string
}

// NewFS returns a blob store rooted at dir (e.g. data/blobs).
func NewFS(root string) *FS {
	return &FS{root: root}
}

// Put writes data to disk and returns its Blake3 digest. Existing identical blobs are not rewritten.
func (f *FS) Put(ctx context.Context, data []byte) ([storage.Blake3DigestLen]byte, error) {
	var zero [storage.Blake3DigestLen]byte
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	hash := blake3.Sum256(data)
	path := f.path(hash)

	if _, err := os.Stat(path); err == nil {
		return hash, nil
	} else if !os.IsNotExist(err) {
		return zero, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return zero, err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "put-*")
	if err != nil {
		return zero, err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return zero, err
	}
	if err := tmp.Close(); err != nil {
		return zero, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return zero, err
	}
	cleanup = false
	return hash, nil
}

// Get reads blob bytes for hash.
func (f *FS) Get(ctx context.Context, hash [storage.Blake3DigestLen]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(f.path(hash))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return data, err
}

// Path returns the on-disk path for hash (for tests and diagnostics).
func (f *FS) Path(hash [storage.Blake3DigestLen]byte) string {
	return f.path(hash)
}

func (f *FS) path(hash [storage.Blake3DigestLen]byte) string {
	prefix := fmt.Sprintf("%02x", hash[0])
	name := hex.EncodeToString(hash[:])
	return filepath.Join(f.root, prefix, name)
}
