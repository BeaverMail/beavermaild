// Package mysql implements storage.Store for MySQL and MariaDB (MySQL protocol).
package mysql

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

// DriverName is the database/sql driver registered by go-sql-driver/mysql.
const DriverName = "mysql"

type schemaMigration struct {
	version int
	file    string
}

// Ordered incremental migrations; version N file runs when current < N.
var schemaMigrations = []schemaMigration{
	{version: 1, file: "migrations/001_init.sql"},
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

// readSchemaVersion returns 0 when the version table is absent or empty.
func readSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var version int
	err := db.QueryRowContext(ctx, "SELECT version FROM `_beaver_schema_version` WHERE id = 1").Scan(&version)
	if err == nil {
		return version, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if isUnknownTable(err) {
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

	for _, stmt := range splitSQLStatements(string(sqlBytes)) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("apply migration %d: %w", m.version, err)
		}
	}
	if err := writeSchemaVersion(ctx, tx, m.version); err != nil {
		return fmt.Errorf("bump schema version %d: %w", m.version, err)
	}
	return tx.Commit()
}

// splitSQLStatements strips -- comments then splits on semicolons.
func splitSQLStatements(script string) []string {
	var cleaned strings.Builder
	for _, line := range strings.Split(script, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "--") {
			continue
		}
		cleaned.WriteString(line)
		cleaned.WriteByte('\n')
	}
	parts := strings.Split(cleaned.String(), ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		stmt := strings.TrimSpace(p)
		if stmt != "" {
			out = append(out, stmt)
		}
	}
	return out
}

func writeSchemaVersion(ctx context.Context, tx *sql.Tx, version int) error {
	_, err := tx.ExecContext(ctx,
		"INSERT INTO `_beaver_schema_version` (id, version) VALUES (1, ?) ON DUPLICATE KEY UPDATE version = VALUES(version)",
		version,
	)
	return err
}

// isUnknownTable reports MySQL/MariaDB "table does not exist" errors.
func isUnknownTable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "doesn't exist") || strings.Contains(msg, "Unknown table")
}
