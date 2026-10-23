// SQLite-backed Store implementation.
package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BeaverMail/beaver/internal/storage"

	_ "modernc.org/sqlite"
)

// getManyChunk caps SQLite bind parameters per IN query.
const getManyChunk = 500

// checkpointInterval is how often the background loop copies the WAL into the database.
const checkpointInterval = time.Second

// Store is a SQLite KV store (one table per subspace).
type Store struct {
	db        *sql.DB
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	// writeMu queues this process's writers in Go: SQLite's busy handler sleeps in fixed steps,
	// so waiting on the file lock costs far more than the commit itself.
	writeMu sync.Mutex
}

var (
	_ storage.Store       = (*Store)(nil)
	_ storage.Snapshotter = (*Store)(nil)
)

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
	s := &Store{db: db, stop: make(chan struct{}), done: make(chan struct{})}
	go s.checkpointLoop()
	return s, nil
}

// checkpointLoop runs PASSIVE checkpoints, which never block readers or writers, so that no
// commit pays for copying a large WAL into the database file.
func (s *Store) checkpointLoop() {
	defer close(s.done)
	t := time.NewTicker(checkpointInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			_, _ = s.db.ExecContext(context.Background(), "PRAGMA wal_checkpoint(PASSIVE)")
		}
	}
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

// GetMany returns existing values for keys using chunked WHERE k IN (...).
func (s *Store) GetMany(ctx context.Context, keys [][]byte) (map[string][]byte, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	table, err := tableForKey(keys[0])
	if err != nil {
		return nil, err
	}
	for _, key := range keys[1:] {
		next, err := tableForKey(key)
		if err != nil {
			return nil, err
		}
		if next != table {
			return nil, fmt.Errorf("sqlite getmany: keys span multiple subspaces")
		}
	}

	out := make(map[string][]byte, len(keys))
	for i := 0; i < len(keys); i += getManyChunk {
		end := i + getManyChunk
		if end > len(keys) {
			end = len(keys)
		}
		chunk := keys[i:end]
		placeholders := strings.Repeat("?,", len(chunk))
		placeholders = placeholders[:len(placeholders)-1]
		query := fmt.Sprintf("SELECT k, v FROM %s WHERE k IN (%s)", table, placeholders)
		args := make([]any, len(chunk))
		for j, key := range chunk {
			args[j] = key
		}
		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var k, v []byte
			if err := rows.Scan(&k, &v); err != nil {
				_ = rows.Close()
				return nil, err
			}
			out[string(k)] = v
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Iterate scans [from, to) in one subspace table and calls fn for each row.
func (s *Store) Iterate(ctx context.Context, from, to []byte, fn func(k, v []byte) error) error {
	return iterate(ctx, s.db, from, to, fn)
}

// Snapshot runs fn with an iterator that reads every range from one snapshot.
// A deferred SQLite tx pins its WAL snapshot at the first read and keeps it until rollback.
func (s *Store) Snapshot(ctx context.Context, fn func(storage.IterateFunc) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return fn(func(ctx context.Context, from, to []byte, fn func(k, v []byte) error) error {
		return iterate(ctx, tx, from, to, fn)
	})
}

// querier is *sql.DB or *sql.Tx.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func iterate(ctx context.Context, q querier, from, to []byte, fn func(k, v []byte) error) error {
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
	rows, err := q.QueryContext(ctx, query, from, to)
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

// commitOnce runs ops in a BEGIN IMMEDIATE transaction: the write lock is taken up front
// (waiting up to busy_timeout), so Assert reads see the latest commit and the read-to-write
// upgrade cannot fail with SQLITE_BUSY, which SQLite returns without waiting.
func (s *Store) commitOnce(ctx context.Context, batch *storage.Batch, ops []storage.BatchOp) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer tx.Close()
	if _, err := tx.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_, _ = tx.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

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

	if _, err := tx.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	done = true
	batch.Reset()
	return nil
}

// SchemaVersion returns the applied KV schema version for this store.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	return SchemaVersion(ctx, s.db)
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Close closes the underlying database.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.done
	})
	return s.db.Close()
}

func readValue(ctx context.Context, tx *sql.Conn, table string, key []byte) ([]byte, error) {
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
