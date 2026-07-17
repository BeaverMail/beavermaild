// Package xfer exports and imports storage.Store KV rows in BEAVERKV1 format.
package xfer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/BeaverMail/beaver/internal/storage"
)

const (
	// Magic is the BEAVERKV1 file signature (includes trailing newline).
	Magic = "BEAVERKV1\n"

	// importBatchSize caps SetRaw ops per Commit.
	importBatchSize = 256
)

var (
	// ErrBadMagic is returned when the dump header is not BEAVERKV1.
	ErrBadMagic = errors.New("xfer: bad magic")
	// ErrSchemaTooNew is returned when dump schema_version exceeds this binary.
	ErrSchemaTooNew = errors.New("xfer: dump schema newer than this binary")
	// ErrNotEmpty is returned when import target already has KV rows and Force is false.
	ErrNotEmpty = errors.New("xfer: store not empty")
)

// ImportOptions controls Import behavior.
type ImportOptions struct {
	// Force allows upsert into a non-empty store.
	Force bool
}

// Export writes all subspace keys from store to w as BEAVERKV1.
// Returns the number of key/value records written.
func Export(ctx context.Context, store storage.Store, w io.Writer) (int, error) {
	if _, err := io.WriteString(w, Magic); err != nil {
		return 0, err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(storage.SchemaVersion))
	if _, err := w.Write(hdr[:]); err != nil {
		return 0, err
	}

	var n int
	var lenBuf [4]byte
	for _, sub := range storage.Subspaces() {
		from, to := subspaceRange(sub)
		err := store.Iterate(ctx, from, to, func(k, v []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(k)))
			if _, err := w.Write(lenBuf[:]); err != nil {
				return err
			}
			if _, err := w.Write(k); err != nil {
				return err
			}
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(v)))
			if _, err := w.Write(lenBuf[:]); err != nil {
				return err
			}
			if _, err := w.Write(v); err != nil {
				return err
			}
			n++
			return nil
		})
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// IsEmpty reports whether every subspace has zero keys (schema table ignored).
func IsEmpty(ctx context.Context, store storage.Store) (bool, error) {
	for _, sub := range storage.Subspaces() {
		from, to := subspaceRange(sub)
		err := store.Iterate(ctx, from, to, func(k, v []byte) error {
			return errStop
		})
		if errors.Is(err, errStop) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

var errStop = errors.New("xfer: stop")

// subspaceRange returns [from, to) covering every key in one subspace.
// Both bounds share the subspace byte (required by sqlite/mysql Iterate).
func subspaceRange(sub byte) (from, to []byte) {
	from = []byte{sub}
	to = make([]byte, 1+512)
	to[0] = sub
	for i := 1; i < len(to); i++ {
		to[i] = 0xff
	}
	return from, to
}

// Import reads a BEAVERKV1 stream from r into store.
// Returns the number of records imported.
func Import(ctx context.Context, store storage.Store, r io.Reader, opts ImportOptions) (int, error) {
	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return 0, fmt.Errorf("xfer: read magic: %w", err)
	}
	if string(magic) != Magic {
		return 0, ErrBadMagic
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, fmt.Errorf("xfer: read schema: %w", err)
	}
	dumpSchema := binary.BigEndian.Uint32(hdr[:])
	if dumpSchema > uint32(storage.SchemaVersion) {
		return 0, fmt.Errorf("%w: dump=%d binary=%d", ErrSchemaTooNew, dumpSchema, storage.SchemaVersion)
	}

	if !opts.Force {
		empty, err := IsEmpty(ctx, store)
		if err != nil {
			return 0, err
		}
		if !empty {
			return 0, ErrNotEmpty
		}
	}

	batch := storage.NewBatch()
	var n int
	var lenBuf [4]byte
	for {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		_, err := io.ReadFull(r, lenBuf[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return n, fmt.Errorf("xfer: read key len: %w", err)
		}
		keyLen := binary.BigEndian.Uint32(lenBuf[:])
		if keyLen > 16<<20 {
			return n, fmt.Errorf("xfer: key length %d too large", keyLen)
		}
		key := make([]byte, keyLen)
		if _, err := io.ReadFull(r, key); err != nil {
			return n, fmt.Errorf("xfer: read key: %w", err)
		}
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return n, fmt.Errorf("xfer: read value len: %w", err)
		}
		valLen := binary.BigEndian.Uint32(lenBuf[:])
		if valLen > 256<<20 {
			return n, fmt.Errorf("xfer: value length %d too large", valLen)
		}
		val := make([]byte, valLen)
		if _, err := io.ReadFull(r, val); err != nil {
			return n, fmt.Errorf("xfer: read value: %w", err)
		}
		if err := batch.SetRaw(key, val); err != nil {
			return n, err
		}
		n++
		if len(batch.Ops()) >= importBatchSize {
			if err := store.Commit(ctx, batch); err != nil {
				return n, err
			}
		}
	}
	if len(batch.Ops()) > 0 {
		if err := store.Commit(ctx, batch); err != nil {
			return n, err
		}
	}
	return n, nil
}
