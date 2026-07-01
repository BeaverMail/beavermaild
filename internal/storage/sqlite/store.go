// SQLite-backed Store implementation.
package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/BeaverMail/beaver/internal/storage"

	_ "modernc.org/sqlite"
)

// Store is a SQLite KV store (one table per subspace).
type Store struct {
	db *sql.DB
}

var _ storage.Store = (*Store)(nil)

// Open opens path, configures pragmas, migrates, and returns a Store.
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open(DriverName, dsn(path))
	if err != nil {
		return nil, err
	}
	if err := Configure(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := Migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Get returns the raw envelope value for key.
func (s *Store) Get(ctx context.Context, key []byte) ([]byte, error) {
	table, err := tableForKey(key)
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf("SELECT v FROM %s WHERE k = ?", table)
	var value []byte
	err = s.db.QueryRowContext(ctx, query, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

// Iterate scans [from, to) in one subspace table and calls fn for each row.
func (s *Store) Iterate(ctx context.Context, from, to []byte, fn func(k, v []byte) error) error {
	if len(from) == 0 || len(to) == 0 {
		return fmt.Errorf("sqlite iterate: empty range bound")
	}
	if from[0] != to[0] {
		return fmt.Errorf("sqlite iterate: subspace mismatch")
	}
	table, err := subspaceTable(from[0])
	if err != nil {
		return err
	}
	query := fmt.Sprintf("SELECT k, v FROM %s WHERE k >= ? AND k < ? ORDER BY k", table)
	rows, err := s.db.QueryContext(ctx, query, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var k, v []byte
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		if err := fn(k, v); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Commit runs all batch ops in one SQL transaction.
func (s *Store) Commit(ctx context.Context, batch *storage.Batch) error {
	ops := batch.Ops()
	if len(ops) == 0 {
		return nil
	}
	return retryBusy(func() error {
		return s.commitOnce(ctx, batch, ops)
	})
}

func (s *Store) commitOnce(ctx context.Context, batch *storage.Batch, ops []storage.BatchOp) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, op := range ops {
		table, err := subspaceTable(op.Subspace)
		if err != nil {
			return err
		}
		switch op.Kind {
		case storage.OpSet:
			q := fmt.Sprintf(`
				INSERT INTO %s (k, v) VALUES (?, ?)
				ON CONFLICT(k) DO UPDATE SET v = excluded.v`, table)
			if _, err := tx.ExecContext(ctx, q, op.Key, op.Value); err != nil {
				return err
			}
		case storage.OpDelete:
			q := fmt.Sprintf("DELETE FROM %s WHERE k = ?", table)
			if _, err := tx.ExecContext(ctx, q, op.Key); err != nil {
				return err
			}
		case storage.OpAssert:
			got, err := readValue(ctx, tx, table, op.Key)
			if err != nil {
				return err
			}
			if !casMatch(got, op.Expect) {
				return storage.ErrCASConflict
			}
		default:
			return fmt.Errorf("sqlite commit: unknown op %d", op.Kind)
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	batch.Reset()
	return nil
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

func readValue(ctx context.Context, tx *sql.Tx, table string, key []byte) ([]byte, error) {
	q := fmt.Sprintf("SELECT v FROM %s WHERE k = ?", table)
	var value []byte
	err := tx.QueryRowContext(ctx, q, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

func casMatch(got, expect []byte) bool {
	if expect == nil {
		return got == nil
	}
	return bytes.Equal(got, expect)
}

func tableForKey(key []byte) (string, error) {
	if len(key) < storage.KeyPrefixLen {
		return "", storage.ErrKeyTooShort
	}
	return subspaceTable(key[0])
}

func subspaceTable(sub byte) (string, error) {
	for _, s := range storage.Subspaces() {
		if s == sub {
			return string([]byte{sub}), nil
		}
	}
	return "", storage.ErrUnknownSubspace
}
