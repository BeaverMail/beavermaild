package storage_test

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/storage"
)

func TestBatchSuffixBuildsKey(t *testing.T) {
	t.Parallel()

	batch := storage.NewBatch().WithAccount(9)
	suffix := storage.BatchSuffix(2, 0x01020304, []byte("tail"))
	if err := batch.Set(storage.SubspaceMail, suffix, []byte("v")); err != nil {
		t.Fatal(err)
	}
	ops := batch.Ops()
	if len(ops) != 1 {
		t.Fatalf("ops %d", len(ops))
	}
	want := storage.AppendKey(nil, storage.SubspaceMail, 9, 0x01020304, 2, []byte("tail"))
	if string(ops[0].Key) != string(want) {
		t.Fatalf("key % x want % x", ops[0].Key, want)
	}
}

func TestBatchRequiresAccount(t *testing.T) {
	t.Parallel()

	batch := storage.NewBatch()
	err := batch.Set(storage.SubspaceMail, storage.BatchSuffix(1, 1, nil), []byte("v"))
	if err != storage.ErrBatchNoAccount {
		t.Fatalf("got %v", err)
	}
}

func TestBatchSetRaw(t *testing.T) {
	t.Parallel()

	key := storage.AppendKey(nil, storage.SubspaceMail, 1, 2, 3, []byte("x"))
	batch := storage.NewBatch()
	if err := batch.SetRaw(key, []byte("v")); err != nil {
		t.Fatal(err)
	}
	ops := batch.Ops()
	if len(ops) != 1 || string(ops[0].Key) != string(key) || string(ops[0].Value) != "v" {
		t.Fatalf("ops=%v", ops)
	}
	if err := batch.SetRaw([]byte{storage.SubspaceMail}, []byte("v")); err != storage.ErrKeyTooShort {
		t.Fatalf("got %v want short", err)
	}
	bad := storage.AppendKey(nil, 'z', 1, 2, 3, nil)
	if err := batch.SetRaw(bad, []byte("v")); err != storage.ErrUnknownSubspace {
		t.Fatalf("got %v want unknown", err)
	}
}

