// Store is the logical KV persistence interface.
package storage

import "context"

// Store provides keyed access to persisted envelope values.
type Store interface {
	Get(ctx context.Context, key []byte) ([]byte, error)
	Iterate(ctx context.Context, from, to []byte, fn func(k, v []byte) error) error
	Commit(ctx context.Context, batch *Batch) error
	Ping(ctx context.Context) error
	Close() error
}
