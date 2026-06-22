// Package app wires config, storage, and process lifecycle for beaver serve.
package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

// App holds runtime resources opened by beaver serve.
type App struct {
	log   *slog.Logger
	cfg   *config.Config
	store storage.Store
	blobs *blob.FS
}

// Open connects storage using cfg and returns an App.
func Open(ctx context.Context, log *slog.Logger, cfg *config.Config) (*App, error) {
	store, err := sqlite.Open(ctx, cfg.StorePath())
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	return &App{
		log:   log,
		cfg:   cfg,
		store: store,
		blobs: blob.NewFS(cfg.BlobDir()),
	}, nil
}

// Store returns the KV store.
func (a *App) Store() storage.Store { return a.store }

// Blobs returns the filesystem blob store.
func (a *App) Blobs() *blob.FS { return a.blobs }

// Run blocks until ctx is canceled, then closes resources.
func (a *App) Run(ctx context.Context) error {
	a.log.Info("beaver ready",
		"data_dir", a.cfg.DataDir,
		"store", a.cfg.StorePath(),
		"blobs", a.cfg.BlobDir(),
	)
	<-ctx.Done()
	a.log.Info("shutting down")
	return a.Close()
}

// Close releases storage handles.
func (a *App) Close() error {
	if a.store != nil {
		return a.store.Close()
	}
	return nil
}
