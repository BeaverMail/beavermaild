// Package app wires config, storage, and process lifecycle for beaver serve.
package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/smtp"
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
	dir   *directory.Local
	inbox *mail.Inbox
	smtp  *smtp.Server
}

// Open connects storage using cfg and returns an App.
func Open(ctx context.Context, log *slog.Logger, cfg *config.Config) (*App, error) {
	store, err := sqlite.Open(ctx, cfg.StorePath())
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	blobs := blob.NewFS(cfg.BlobDir())
	dir := directory.NewLocal(store)
	inbox := mail.NewInbox(store, blobs)
	return &App{
		log:   log,
		cfg:   cfg,
		store: store,
		blobs: blobs,
		dir:   dir,
		inbox: inbox,
		smtp:  smtp.NewServer(log, cfg.SMTPListen(), dir, inbox),
	}, nil
}

// Store returns the KV store.
func (a *App) Store() storage.Store { return a.store }

// Blobs returns the filesystem blob store.
func (a *App) Blobs() *blob.FS { return a.blobs }

// Run blocks until ctx is canceled, then closes resources.
func (a *App) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- a.smtp.Serve(ctx) }()

	a.log.Info("beaver ready",
		"data_dir", a.cfg.DataDir,
		"store", a.cfg.StorePath(),
		"blobs", a.cfg.BlobDir(),
		"smtp", a.cfg.SMTPListen(),
	)

	select {
	case <-ctx.Done():
		a.log.Info("shutting down")
		return a.Close()
	case err := <-errCh:
		if err != nil {
			a.log.Error("smtp stopped", slog.Any("err", err))
		}
		return a.Close()
	}
}

// Close releases storage handles.
func (a *App) Close() error {
	if a.store != nil {
		return a.store.Close()
	}
	return nil
}
