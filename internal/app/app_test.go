package app_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/app"
	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/log"
)

func TestAppOpenAndShutdown(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg, err := config.InitLayout(filepath.Join(dir, "config.json"), dir, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.HTTP.Enabled = false // init enables loopback :8080; avoid binding a fixed port in tests

	ctx, cancel := context.WithCancel(context.Background())

	a, err := app.Open(ctx, log.New("error"), cfg)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	time.Sleep(20 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
