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
