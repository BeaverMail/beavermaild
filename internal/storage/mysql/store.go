// MySQL/MariaDB-backed Store implementation (one InnoDB table per subspace).
package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/internal/storage"

	"github.com/go-sql-driver/mysql"
)

// getManyChunk caps bind parameters per IN query.
const getManyChunk = 500

// Store is a MySQL/MariaDB KV store (one table per subspace).
type Store struct {
	db *sql.DB
}

var (
	_ storage.Store       = (*Store)(nil)
	_ storage.Snapshotter = (*Store)(nil)
)

// Open connects with dsn, migrates schema, and returns a Store.
// DSN format: user:pass@tcp(host:3306)/dbname?parseTime=true (go-sql-driver/mysql).
func Open(ctx context.Context, dsn string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("mysql: empty dsn")
	}
	db, err := sql.Open(DriverName, dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("mysql ping: %w", err)
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
	query := fmt.Sprintf("SELECT `v` FROM `%s` WHERE `k` = ?", table)
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
			return nil, fmt.Errorf("mysql getmany: keys span multiple subspaces")
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
		query := fmt.Sprintf("SELECT `k`, `v` FROM `%s` WHERE `k` IN (%s)", table, placeholders)
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
// InnoDB REPEATABLE READ keeps the snapshot taken at the first read for the whole tx.
func (s *Store) Snapshot(ctx context.Context, fn func(storage.IterateFunc) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
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
		return fmt.Errorf("mysql iterate: empty range bound")
	}
	if from[0] != to[0] {
		return fmt.Errorf("mysql iterate: subspace mismatch")
	}
	table, err := subspaceTable(from[0])
	if err != nil {
		return err
	}
	query := fmt.Sprintf("SELECT `k`, `v` FROM `%s` WHERE `k` >= ? AND `k` < ? ORDER BY `k`", table)
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

// Commit runs all batch ops in one SQL transaction, retrying it when InnoDB aborts
// it for a lock or snapshot conflict (concurrent CAS on the same key).
func (s *Store) Commit(ctx context.Context, batch *storage.Batch) error {
	ops := batch.Ops()
	if len(ops) == 0 {
		return nil
	}
	var err error
	for attempt := 0; attempt < conflictRetryAttempts; attempt++ {
		err = s.commitOnce(ctx, batch, ops)
		if !isTxConflict(err) {
			return err
		}
		time.Sleep(conflictRetryBase * time.Duration(attempt+1))
	}
	return err
}

const (
	conflictRetryAttempts = 12
	conflictRetryBase     = 5 * time.Millisecond
)

// isTxConflict reports deadlock (1213) or MariaDB snapshot-isolation conflict (1020).
func isTxConflict(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && (me.Number == 1213 || me.Number == 1020)
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
			// VALUES(v) keeps MariaDB and older MySQL happy (alias form needs 8.0.19+).
			q := fmt.Sprintf(
				"INSERT INTO `%s` (`k`, `v`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `v` = VALUES(`v`)",
				table,
			)
			if _, err := tx.ExecContext(ctx, q, op.Key, op.Value); err != nil {
				return err
			}
		case storage.OpDelete:
			q := fmt.Sprintf("DELETE FROM `%s` WHERE `k` = ?", table)
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
			return fmt.Errorf("mysql commit: unknown op %d", op.Kind)
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
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
	return s.db.Close()
}

// readValue is a locking read: a plain SELECT sees the tx snapshot and would let two CAS pass.
func readValue(ctx context.Context, tx *sql.Tx, table string, key []byte) ([]byte, error) {
	q := fmt.Sprintf("SELECT `v` FROM `%s` WHERE `k` = ? FOR UPDATE", table)
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
