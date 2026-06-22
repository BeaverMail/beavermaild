// SQLite storage driver: migrations and connection setup.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DriverName is the database/sql driver for modernc SQLite.
const DriverName = "sqlite"

type schemaMigration struct {
	version int
	file    string
}

// Ordered incremental migrations; version N file runs when current < N.
var schemaMigrations = []schemaMigration{
	{version: 1, file: "migrations/001_init.sql"},
}

// Configure applies SQLite pragmas for BeaverMail (WAL, sync, busy timeout).
func Configure(ctx context.Context, db *sql.DB) error {
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=30000",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("sqlite pragma %q: %w", pragma, err)
		}
	}
	return nil
}

// Migrate applies pending schema migrations based on _beaver_schema_version.
func Migrate(ctx context.Context, db *sql.DB) error {
	current, err := readSchemaVersion(ctx, db)
	if err != nil {
		return err
	}
	for _, m := range schemaMigrations {
		if m.version <= current {
			continue
		}
		if m.version != current+1 {
			return fmt.Errorf("schema version %d: missing migration %d", current, current+1)
		}
		if err := applySchemaMigration(ctx, db, m); err != nil {
			return err
		}
		current = m.version
	}
	return nil
}

// SchemaVersion reads the stored schema version (Migrate must have run first).
func SchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	return readSchemaVersion(ctx, db)
}

// readSchemaVersion returns 0 when _beaver_schema_version is absent or empty.
func readSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var version int
	err := db.QueryRowContext(ctx, "SELECT version FROM _beaver_schema_version WHERE id = 1").Scan(&version)
	if err == nil {
		return version, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if isNoSuchTable(err) {
		return 0, nil
	}
	return 0, fmt.Errorf("read schema version: %w", err)
}

func applySchemaMigration(ctx context.Context, db *sql.DB, m schemaMigration) error {
	sqlBytes, err := migrationFS.ReadFile(m.file)
	if err != nil {
		return fmt.Errorf("read migration %d: %w", m.version, err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("apply migration %d: %w", m.version, err)
	}
	if err := writeSchemaVersion(ctx, tx, m.version); err != nil {
		return fmt.Errorf("bump schema version %d: %w", m.version, err)
	}
	return tx.Commit()
}

func writeSchemaVersion(ctx context.Context, tx *sql.Tx, version int) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO _beaver_schema_version (id, version) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET version = excluded.version`, version)
	return err
}

func isNoSuchTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}
