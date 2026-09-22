package security_test

import (
	"sync"
	"testing"

	"github.com/BeaverMail/beaver/internal/security"
)

func TestConnLimiterBlocksWhenFull(t *testing.T) {
	t.Parallel()
	lim := security.NewConnLimiter(2)
	if !lim.Acquire() || !lim.Acquire() {
		t.Fatal("expected acquire")
	}
	if lim.Acquire() {
		t.Fatal("expected full")
	}
	lim.Release()
	if !lim.Acquire() {
		t.Fatal("expected acquire after release")
	}
}

func TestConnLimiterNilUnlimited(t *testing.T) {
	t.Parallel()
	var lim *security.ConnLimiter
	if !lim.Acquire() {
		t.Fatal("nil should allow")
	}
	lim.Release()
	if security.NewConnLimiter(0) != nil {
		t.Fatal("max<=0 should be nil")
	}
}

func TestConnLimiterConcurrent(t *testing.T) {
	t.Parallel()
	lim := security.NewConnLimiter(5)
	var wg sync.WaitGroup
	var okCount int
	var mu sync.Mutex
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if lim.Acquire() {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if okCount != 5 {
		t.Fatalf("okCount=%d want 5", okCount)
	}
}
