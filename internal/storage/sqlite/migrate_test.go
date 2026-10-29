package sqlite_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"

	_ "modernc.org/sqlite"
)

func TestMigrateSetsSchemaVersion(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)
	ctx := context.Background()

	version, err := sqlite.SchemaVersion(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		t.Fatalf("version before migrate: got %d want 0", version)
	}

	if err := sqlite.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	version, err = sqlite.SchemaVersion(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if version != storage.SchemaVersion {
		t.Fatalf("version after migrate: got %d want %d", version, storage.SchemaVersion)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)
	ctx := context.Background()

	if err := sqlite.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := sqlite.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	version, err := sqlite.SchemaVersion(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if version != storage.SchemaVersion {
		t.Fatalf("version %d want %d", version, storage.SchemaVersion)
	}
}

func TestMigrateSkipsWhenVersionCurrent(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)
	ctx := context.Background()

	if err := sqlite.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	// Drop a data table; version row still says current — Migrate must not re-run.
	if _, err := db.ExecContext(ctx, "DROP TABLE m"); err != nil {
		t.Fatal(err)
	}
	if err := sqlite.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	var name string
	err := db.QueryRowContext(ctx,
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'm'",
	).Scan(&name)
	if err != sql.ErrNoRows {
		t.Fatal("expected m to stay dropped when schema version is current")
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open(sqlite.DriverName, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := sqlite.Configure(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db
}
