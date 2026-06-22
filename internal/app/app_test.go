package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/app"
	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/log"
)

func TestAppOpenAndShutdown(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg, err := config.InitLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

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
