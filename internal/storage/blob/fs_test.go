package blob_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/storage/blob"
)

func TestFSPutGetRoundtrip(t *testing.T) {
	t.Parallel()

	fs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	ctx := context.Background()
	data := []byte("large mail body")

	hash, err := fs.Put(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.Get(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %q want %q", got, data)
	}
}

func TestFSPathLayout(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	fs := blob.NewFS(root)
	ctx := context.Background()

	hash, err := fs.Put(ctx, []byte{0xAB, 0xCD})
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(root, fmt.Sprintf("%02x", hash[0]), hex32(hash))
	if fs.Path(hash) != want {
		t.Fatalf("path %q want %q", fs.Path(hash), want)
	}
}

func TestFSPutDedup(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "blobs")
	fs := blob.NewFS(root)
	ctx := context.Background()
	data := bytes.Repeat([]byte{'x'}, 100)

	h1, err := fs.Put(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := fs.Put(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("hash mismatch on dedup")
	}

	var count int
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			count++
		}
		return nil
	})
	if count != 1 {
		t.Fatalf("file count %d want 1", count)
	}
}

func TestFSGetNotFound(t *testing.T) {
	t.Parallel()

	fs := blob.NewFS(t.TempDir())
	ctx := context.Background()

	var hash [32]byte
	hash[0] = 0x01
	_, err := fs.Get(ctx, hash)
	if err != blob.ErrNotFound {
		t.Fatalf("got %v want %v", err, blob.ErrNotFound)
	}
}

func TestRouteInlineVsFS(t *testing.T) {
	t.Parallel()

	fs := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	ctx := context.Background()

	small := []byte("small")
	ref, err := blob.Put(ctx, fs, small)
	if err != nil {
		t.Fatal(err)
	}
	if !ref.Inline || !bytes.Equal(ref.Data, small) {
		t.Fatalf("inline ref %+v", ref)
	}

	large := bytes.Repeat([]byte{'z'}, blob.InlineThreshold)
	ref, err = blob.Put(ctx, fs, large)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Inline {
		t.Fatal("expected fs ref")
	}
	got, err := blob.Get(ctx, fs, ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, large) {
		t.Fatalf("len %d want %d", len(got), len(large))
	}
}

func hex32(h [32]byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0f]
	}
	return string(out)
}

// TestWriterStreams: a blob written in pieces gets the digest Put gives the whole data, an identical
// blob is reused, and Abort leaves no temp file.
func TestWriterStreams(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "blobs")
	fs := blob.NewFS(root)
	ctx := context.Background()
	data := bytes.Repeat([]byte("0123456789"), 10000)
	want, err := fs.Put(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 { // reusing the blob Put left, then fresh
		w, err := fs.Create(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < len(data); i += 333 {
			if _, err := w.Write(data[i:min(i+333, len(data))]); err != nil {
				t.Fatal(err)
			}
		}
		got, err := w.Commit()
		w.Abort() // after Commit: no effect
		if err != nil || got != want {
			t.Fatalf("Commit = %x, %v; want %x", got, err, want)
		}
		if b, err := fs.Get(ctx, got); err != nil || !bytes.Equal(b, data) {
			t.Fatalf("Get after Commit: %v", err)
		}
		_ = fs.Remove(want)
	}
	w, err := fs.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(data)
	w.Abort()
	if left, _ := filepath.Glob(filepath.Join(root, "put-*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}
