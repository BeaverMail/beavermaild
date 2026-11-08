package sqlite_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
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

// Rows committed after the snapshot's first read stay invisible to it, in every subspace.
func TestStoreSnapshotIgnoresLaterWrites(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account := uint32(3)
	put := func(sub byte, doc uint32) {
		t.Helper()
		batch := storage.NewBatch().WithAccount(account)
		if err := batch.Set(sub, storage.BatchSuffix(1, doc, nil), []byte("v")); err != nil {
			t.Fatal(err)
		}
		if err := store.Commit(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	count := func(iterate storage.IterateFunc, sub byte) int {
		t.Helper()
		from := storage.AppendKeyPrefix(nil, sub, account, 0, 0, 5)
		to := storage.AppendKeyPrefix(nil, sub, account+1, 0, 0, 5)
		var n int
		if err := iterate(ctx, from, to, func(k, v []byte) error { n++; return nil }); err != nil {
			t.Fatal(err)
		}
		return n
	}

	put(storage.SubspaceMail, 1)
	err = store.Snapshot(ctx, func(iterate storage.IterateFunc) error {
		if n := count(iterate, storage.SubspaceMail); n != 1 {
			t.Fatalf("mail rows before write: %d", n)
		}
		put(storage.SubspaceMail, 2)
		put(storage.SubspaceAdmin, 1)
		if n := count(iterate, storage.SubspaceMail); n != 1 {
			t.Errorf("snapshot sees %d mail rows, want 1", n)
		}
		if n := count(iterate, storage.SubspaceAdmin); n != 0 {
			t.Errorf("snapshot sees %d admin rows, want 0", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := count(store.Iterate, storage.SubspaceAdmin); n != 1 {
		t.Fatalf("admin rows after snapshot: %d, want 1", n)
	}
}

// The background checkpoint lets the WAL restart, so a second equal burst reuses the file
// instead of growing it (commits themselves never checkpoint).
func TestStoreWALCheckpointedInBackground(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	store, err := sqlite.Open(ctx, "file:"+dir+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	burst := func(fill byte) int64 {
		t.Helper()
		// Distinct bytes per burst: SQLite skips writing a row whose value is unchanged.
		value := bytes.Repeat([]byte{fill}, 1024)
		for i := uint32(0); i < 2000; i++ {
			batch := storage.NewBatch().WithAccount(1)
			if err := batch.Set(storage.SubspaceMail, storage.BatchSuffix(1, i, nil), value); err != nil {
				t.Fatal(err)
			}
			if err := store.Commit(ctx, batch); err != nil {
				t.Fatal(err)
			}
		}
		st, err := os.Stat(dir + "/store.sqlite-wal")
		if err != nil {
			t.Fatal(err)
		}
		return st.Size()
	}

	first := burst('a')
	time.Sleep(2500 * time.Millisecond)
	second := burst('b')
	if second > first+first/4 {
		t.Fatalf("WAL grew from %d to %d bytes: not checkpointed between bursts", first, second)
	}
}
