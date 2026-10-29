package config_test

import (
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/config"
)

func TestParseDurationDays(t *testing.T) {
	t.Parallel()

	d, err := config.ParseDuration("3d")
	if err != nil {
		t.Fatal(err)
	}
	if d != 3*24*time.Hour {
		t.Fatalf("got %v", d)
	}
}

func TestQueuePolicyDefaults(t *testing.T) {
	t.Parallel()

	cfg := config.Default("data")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	qt, err := cfg.QueueTimings()
	if err != nil {
		t.Fatal(err)
	}
	if len(qt.RetryIntervals) != 9 || qt.RetryIntervals[0] != 2*time.Minute {
		t.Fatalf("intervals %+v", qt.RetryIntervals)
	}
	if qt.MaxLifetime != 3*24*time.Hour {
		t.Fatalf("lifetime %v", qt.MaxLifetime)
	}
	if qt.RunDelay != time.Second {
		t.Fatalf("run delay %v", qt.RunDelay)
	}
}
