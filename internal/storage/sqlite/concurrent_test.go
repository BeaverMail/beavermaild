package sqlite_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

func TestConcurrentWritersSameDB(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.sqlite")
	storeA, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeA.Close() })
	storeB, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeB.Close() })

	const n = 40
	var wg sync.WaitGroup
	errCh := make(chan error, n*2)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			batch := storage.NewBatch().WithAccount(1)
			suffix := storage.BatchSuffix(1, uint32(i), nil)
			if err := batch.Set(storage.SubspaceMail, suffix, []byte("a")); err != nil {
				errCh <- err
				return
			}
			errCh <- storeA.Commit(ctx, batch)
		}(i)
		go func(i int) {
			defer wg.Done()
			batch := storage.NewBatch().WithAccount(2)
			suffix := storage.BatchSuffix(1, uint32(i), nil)
			if err := batch.Set(storage.SubspaceMail, suffix, []byte("b")); err != nil {
				errCh <- err
				return
			}
			errCh <- storeB.Commit(ctx, batch)
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}
