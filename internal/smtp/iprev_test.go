package smtp

import (
	"context"
	"testing"
	"time"
)

func TestLookupIPRevLoopback(t *testing.T) {
	ptr, res := LookupIPRev(context.Background(), "127.0.0.1", time.Second)
	if ptr != "" || res != IPRevPass {
		t.Fatalf("ptr=%q res=%q", ptr, res)
	}
}
