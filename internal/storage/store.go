// Store is the logical KV persistence interface.
package storage

import "context"

// Store provides keyed access to persisted envelope values.
type Store interface {
	Get(ctx context.Context, key []byte) ([]byte, error)
	// GetMany loads values for keys in one or more queries. Missing keys are omitted.
	// All keys must belong to the same subspace table.
	GetMany(ctx context.Context, keys [][]byte) (map[string][]byte, error)
	Iterate(ctx context.Context, from, to []byte, fn func(k, v []byte) error) error
	Commit(ctx context.Context, batch *Batch) error
	Ping(ctx context.Context) error
	Close() error
}

// IterateFunc scans [from, to) in one subspace, with the same contract as Store.Iterate.
type IterateFunc func(ctx context.Context, from, to []byte, fn func(k, v []byte) error) error

// Snapshotter is implemented by stores that can read several ranges from one
// consistent point in time while writers keep committing.
type Snapshotter interface {
	Snapshot(ctx context.Context, fn func(iterate IterateFunc) error) error
}
