// Routed blob reference: inline KV payload or filesystem hash pointer.
package blob

import (
	"context"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// Ref is either inline bytes (< InlineThreshold) or a Blake3 hash on fs.
type Ref struct {
	Inline bool
	Hash   [storage.Blake3DigestLen]byte
	Data   []byte
}

// Put routes data to inline or filesystem storage.
func Put(ctx context.Context, fs *FS, data []byte) (Ref, error) {
	if len(data) < InlineThreshold {
		return Ref{Inline: true, Data: append([]byte(nil), data...)}, nil
	}
	hash, err := fs.Put(ctx, data)
	if err != nil {
		return Ref{}, err
	}
	return Ref{Hash: hash}, nil
}

// Get loads bytes from a Ref.
func Get(ctx context.Context, fs *FS, ref Ref) ([]byte, error) {
	if ref.Inline {
		return append([]byte(nil), ref.Data...), nil
	}
	return fs.Get(ctx, ref.Hash)
}
