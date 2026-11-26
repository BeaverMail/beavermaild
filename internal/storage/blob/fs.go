// Package blob stores large payloads on the filesystem (content-addressed Blake3).
package blob

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BeaverMail/beavermaild/internal/storage"
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

// Put writes data to disk and returns its Blake3 digest. Existing identical blobs are not rewritten,
// only touched (see GC).
func (f *FS) Put(ctx context.Context, data []byte) ([storage.Blake3DigestLen]byte, error) {
	var zero [storage.Blake3DigestLen]byte
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	hash := blake3.Sum256(data)
	if reused, err := f.reuse(hash); reused || err != nil {
		return hash, err
	}
	w, err := f.Create(ctx)
	if err != nil {
		return zero, err
	}
	defer w.Abort()
	if _, err := w.Write(data); err != nil {
		return zero, err
	}
	return w.Commit()
}

// reuse reports whether the blob for hash exists already. Reused: a fresh mtime keeps GC from
// removing it before the new row commits.
func (f *FS) reuse(hash [storage.Blake3DigestLen]byte) (bool, error) {
	_, err := os.Stat(f.path(hash))
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	now := time.Now()
	return true, os.Chtimes(f.path(hash), now, now)
}

// Writer streams a blob to a temp file, hashing it on the way, so a large upload never sits in
// memory. Commit installs it under its hash; Abort (safe after Commit) drops it. An interrupted
// writer leaves a put-* file that GC removes.
type Writer struct {
	f    *FS
	tmp  *os.File
	hash *blake3.Hasher
	done bool
}

// Create starts a blob Writer.
func (f *FS) Create(ctx context.Context) (*Writer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(f.root, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(f.root, "put-*")
	if err != nil {
		return nil, err
	}
	return &Writer{f: f, tmp: tmp, hash: blake3.New()}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	n, err := w.tmp.Write(p)
	_, _ = w.hash.Write(p[:n])
	return n, err
}

// Name is the temp file's path, to read the data back before Commit.
func (w *Writer) Name() string { return w.tmp.Name() }

// Commit installs the blob under its Blake3 digest and returns the digest. An identical blob
// already stored is kept (and touched) and the temp file dropped.
func (w *Writer) Commit() ([storage.Blake3DigestLen]byte, error) {
	var hash [storage.Blake3DigestLen]byte
	copy(hash[:], w.hash.Sum(nil))
	if err := w.tmp.Close(); err != nil {
		w.Abort()
		return hash, err
	}
	w.done = true
	if reused, err := w.f.reuse(hash); reused || err != nil {
		_ = os.Remove(w.tmp.Name())
		return hash, err
	}
	path := w.f.path(hash)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		_ = os.Remove(w.tmp.Name())
		return hash, err
	}
	if err := os.Rename(w.tmp.Name(), path); err != nil {
		_ = os.Remove(w.tmp.Name())
		return hash, err
	}
	return hash, nil
}

// Abort drops an uncommitted blob.
func (w *Writer) Abort() {
	if w.done {
		return
	}
	w.done = true
	_ = w.tmp.Close()
	_ = os.Remove(w.tmp.Name())
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

// Open returns the blob for streaming; the caller closes it.
func (f *FS) Open(ctx context.Context, hash [storage.Blake3DigestLen]byte) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(f.path(hash))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return file, err
}

// Path returns the on-disk path for hash (for tests and diagnostics).
func (f *FS) Path(hash [storage.Blake3DigestLen]byte) string {
	return f.path(hash)
}

// Remove deletes the blob file for hash; missing files are ignored.
func (f *FS) Remove(hash [storage.Blake3DigestLen]byte) error {
	err := os.Remove(f.path(hash))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (f *FS) path(hash [storage.Blake3DigestLen]byte) string {
	prefix := fmt.Sprintf("%02x", hash[0])
	name := hex.EncodeToString(hash[:])
	return filepath.Join(f.root, prefix, name)
}
