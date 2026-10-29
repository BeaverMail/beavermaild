package directory_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// Two directories on one store file stand in for the daemon and a CLI process.
func TestConcurrentCreateDomainUniqueIDs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := "file:" + t.TempDir() + "/store.sqlite"
	var dirs [2]*directory.Local
	for i := range dirs {
		store, err := sqlite.Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		dirs[i] = directory.NewLocal(store)
	}

	const n = 20
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := dirs[i%2].CreateDomain(ctx, 1, fmt.Sprintf("d%d.example.com", i))
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	domains, err := dirs[0].ListDomains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint32]string{}
	for _, dom := range domains {
		if prev, ok := seen[dom.ID]; ok {
			t.Fatalf("id %d shared by %s and %s", dom.ID, prev, dom.Name)
		}
		seen[dom.ID] = dom.Name
	}
	if len(domains) != n {
		t.Fatalf("got %d domains, want %d", len(domains), n)
	}
}
