// Package openstore opens a storage.Store from driver name and connection settings.
package openstore

import (
	"context"
	"fmt"
	"strings"

	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/mysql"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

// Open connects to the KV backend named by driver (sqlite or mysql).
// For sqlite, path is the database file; for mysql, dsn is the go-sql-driver DSN.
func Open(ctx context.Context, driver, path, dsn string) (storage.Store, error) {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "", config.StoreDriverSQLite:
		if strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("openstore: sqlite path required")
		}
		return sqlite.Open(ctx, path)
	case config.StoreDriverMySQL:
		return mysql.Open(ctx, dsn)
	default:
		return nil, fmt.Errorf("openstore: unknown driver %q", driver)
	}
}

// OpenConfig opens the store described by cfg (same rules as beaver serve).
func OpenConfig(ctx context.Context, cfg *config.Config) (storage.Store, error) {
	switch cfg.StoreDriver() {
	case config.StoreDriverSQLite:
		return Open(ctx, config.StoreDriverSQLite, cfg.StorePath(), "")
	case config.StoreDriverMySQL:
		return Open(ctx, config.StoreDriverMySQL, "", cfg.StoreDSN())
	default:
		return nil, fmt.Errorf("openstore: unknown driver %q", cfg.StoreDriver())
	}
}
