package mysql_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/mysql"
)

// openStore opens a MariaDB/MySQL store or skips when BEAVER_TEST_MYSQL_DSN is unset.
func openStore(t *testing.T) *mysql.Store {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("BEAVER_TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("set BEAVER_TEST_MYSQL_DSN to run MySQL/MariaDB store tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := mysql.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestStorePutGet(t *testing.T) {
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
	store := openStore(t)
	ctx := context.Background()

	key := storage.AppendKey(nil, storage.SubspaceMail, 1, 2, 3, nil)
	_, err := store.Get(ctx, key)
	if err != storage.ErrNotFound {
		t.Fatalf("got %v want %v", err, storage.ErrNotFound)
	}
}

func TestStoreIterateRange(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()
	account := uint32(3)

	for _, doc := range []uint32{1, 2, 3, 4} {
		batch := storage.NewBatch().WithAccount(account)
		suffix := storage.BatchSuffix(2, doc, nil)
		if err := batch.Set(storage.SubspaceMail, suffix, []byte{byte(doc)}); err != nil {
			t.Fatal(err)
		}
		if err := store.Commit(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}

	from := storage.AppendKey(nil, storage.SubspaceMail, account, 2, 2, nil)
	to := storage.AppendKey(nil, storage.SubspaceMail, account, 4, 2, nil)
	var docs []byte
	err := store.Iterate(ctx, from, to, func(k, v []byte) error {
		docs = append(docs, v...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(docs, []byte{2, 3}) {
		t.Fatalf("got %v want [2 3]", docs)
	}
}

func TestStoreDelete(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	suffix := storage.BatchSuffix(1, 50, nil)
	batch := storage.NewBatch().WithAccount(1)
	if err := batch.Set(storage.SubspaceMail, suffix, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, batch); err != nil {
		t.Fatal(err)
	}

	batch = storage.NewBatch().WithAccount(1)
	if err := batch.Delete(storage.SubspaceMail, suffix); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, batch); err != nil {
		t.Fatal(err)
	}

	key := storage.AppendKey(nil, storage.SubspaceMail, 1, 50, 1, nil)
	_, err := store.Get(ctx, key)
	if err != storage.ErrNotFound {
		t.Fatalf("got %v want not found", err)
	}
}

func TestStoreCAS(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()
	suffix := storage.BatchSuffix(1, 1, nil)

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

func TestStoreOpenEmptyDSN(t *testing.T) {
	_, err := mysql.Open(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestStorePing(t *testing.T) {
	store := openStore(t)
	if err := store.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}
