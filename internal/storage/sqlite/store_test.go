package sqlite_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestStorePutGet(t *testing.T) {
	t.Parallel()

	store := openStore(t)
	ctx := context.Background()

	suffix := storage.BatchSuffix(1, 100, nil)
	value := []byte("envelope-bytes")

	batch := storage.NewBatch().WithAccount(7)
	if err := batch.Set(storage.SubspaceMail, suffix, value); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, batch); err != nil {
		t.Fatal(err)
	}

	key := storage.AppendKey(nil, storage.SubspaceMail, 7, 100, 1, nil)
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("got %q want %q", got, value)
	}
}

func TestStoreGetMany(t *testing.T) {
	t.Parallel()

	store := openStore(t)
	ctx := context.Background()
	account := uint32(9)

	for _, doc := range []uint32{1, 2, 4} {
		batch := storage.NewBatch().WithAccount(account)
		suffix := storage.BatchSuffix(2, doc, nil)
		val := []byte{byte(doc)}
		if err := batch.Set(storage.SubspaceMail, suffix, val); err != nil {
			t.Fatal(err)
		}
		if err := store.Commit(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}

	keys := [][]byte{
		storage.AppendKey(nil, storage.SubspaceMail, account, 1, 2, nil),
		storage.AppendKey(nil, storage.SubspaceMail, account, 2, 2, nil),
		storage.AppendKey(nil, storage.SubspaceMail, account, 3, 2, nil),
		storage.AppendKey(nil, storage.SubspaceMail, account, 4, 2, nil),
	}
	got, err := store.GetMany(ctx, keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d values want 3", len(got))
	}
	if !bytes.Equal(got[string(keys[0])], []byte{1}) {
		t.Fatalf("doc 1: %q", got[string(keys[0])])
	}
	if !bytes.Equal(got[string(keys[1])], []byte{2}) {
		t.Fatalf("doc 2: %q", got[string(keys[1])])
	}
	if _, ok := got[string(keys[2])]; ok {
		t.Fatal("missing key 3 should be omitted")
	}
	if !bytes.Equal(got[string(keys[3])], []byte{4}) {
		t.Fatalf("doc 4: %q", got[string(keys[3])])
	}
}

func TestStoreGetNotFound(t *testing.T) {
	t.Parallel()

	store := openStore(t)
	ctx := context.Background()

	key := storage.AppendKey(nil, storage.SubspaceMail, 1, 2, 3, nil)
	_, err := store.Get(ctx, key)
	if err != storage.ErrNotFound {
		t.Fatalf("got %v want %v", err, storage.ErrNotFound)
	}
}

func TestStoreIterateRange(t *testing.T) {
	t.Parallel()

	store := openStore(t)
	ctx := context.Background()

	account := uint32(5)
	for _, doc := range []uint32{10, 11, 12} {
		batch := storage.NewBatch().WithAccount(account)
		suffix := storage.BatchSuffix(2, doc, nil)
		val := []byte{byte(doc)}
		if err := batch.Set(storage.SubspaceMail, suffix, val); err != nil {
			t.Fatal(err)
		}
		if err := store.Commit(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}

	from := storage.AppendKeyPrefix(nil, storage.SubspaceMail, account, 0, 2, 6)
	to := storage.AppendKey(nil, storage.SubspaceMail, account, 99, 2, nil)

	var keys [][]byte
	err := store.Iterate(ctx, from, to, func(k, v []byte) error {
		keys = append(keys, append([]byte(nil), k...))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("got %d keys want 3", len(keys))
	}
}

func TestStoreAssertCAS(t *testing.T) {
	t.Parallel()

	store := openStore(t)
	ctx := context.Background()

	suffix := storage.BatchSuffix(1, 50, nil)
	value := []byte("v1")
	key := storage.AppendKey(nil, storage.SubspaceMail, 3, 50, 1, nil)

	batch := storage.NewBatch().WithAccount(3)
	if err := batch.Set(storage.SubspaceMail, suffix, value); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, batch); err != nil {
		t.Fatal(err)
	}

	// assert ok + update
	batch = storage.NewBatch().WithAccount(3)
	if err := batch.Assert(storage.SubspaceMail, suffix, value); err != nil {
		t.Fatal(err)
	}
	next := []byte("v2")
	if err := batch.Set(storage.SubspaceMail, suffix, next); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, batch); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, next) {
		t.Fatalf("got %q want %q", got, next)
	}

	// assert fail rolls back whole batch
	batch = storage.NewBatch().WithAccount(3)
	if err := batch.Assert(storage.SubspaceMail, suffix, []byte("stale")); err != nil {
		t.Fatal(err)
	}
	if err := batch.Set(storage.SubspaceMail, suffix, []byte("v3")); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, batch); err != storage.ErrCASConflict {
		t.Fatalf("got %v want %v", err, storage.ErrCASConflict)
	}

	got, err = store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, next) {
		t.Fatalf("value changed after failed commit: %q", got)
	}
}

func TestStoreAssertAbsent(t *testing.T) {
	t.Parallel()

	store := openStore(t)
	ctx := context.Background()

	suffix := storage.BatchSuffix(4, 9, []byte("x"))
	batch := storage.NewBatch().WithAccount(1)
	if err := batch.Assert(storage.SubspaceMail, suffix, nil); err != nil {
		t.Fatal(err)
	}
	if err := batch.Set(storage.SubspaceMail, suffix, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, batch); err != nil {
		t.Fatal(err)
	}

	batch = storage.NewBatch().WithAccount(1)
	if err := batch.Assert(storage.SubspaceMail, suffix, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, batch); err != storage.ErrCASConflict {
		t.Fatalf("got %v want %v", err, storage.ErrCASConflict)
	}
}

func openStore(t *testing.T) *sqlite.Store {
	t.Helper()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
