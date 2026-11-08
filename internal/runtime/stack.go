// Package runtime opens Beaver data stores for CLI tools and the plugin host.
package runtime

import (
	"context"
	"fmt"

	"github.com/BeaverMail/beavermaild/internal/config"
	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// Stack holds opened config, store, directory, and mail helpers for one CLI session.
type Stack struct {
	Cfg   *config.Config
	Store storage.Store
	Blobs *blob.FS
	Dir   *directory.Local
	Inbox *mail.Inbox
}

// OpenMailStack loads config and opens the configured storage backend + blob FS (host process only).
func OpenMailStack(ctx context.Context, configPath string) (*Stack, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	store, err := sqlite.Open(ctx, cfg.StorePath())
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	blobs := blob.NewFS(cfg.BlobDir())
	dir := directory.NewLocal(store)
	inbox := mail.NewInbox(store, blobs)
	inbox.SetQuotaDefaults(mail.QuotaDefaults{
		StorageBytes: cfg.Quota.DefaultStorageBytes,
		Messages:     cfg.Quota.DefaultMessages,
	})
	return &Stack{
		Cfg:   cfg,
		Store: store,
		Blobs: blobs,
		Dir:   dir,
		Inbox: inbox,
	}, nil
}

// Close releases the store handle.
func (s *Stack) Close() error {
	if s.Store != nil {
		return s.Store.Close()
	}
	return nil
}

// AccountID resolves an existing mailbox email to its account id.
func (s *Stack) AccountID(ctx context.Context, email string) (uint32, error) {
	acc, _, err := s.Dir.ResolveEmail(ctx, email)
	if err != nil {
		return 0, err
	}
	return acc.ID, nil
}
