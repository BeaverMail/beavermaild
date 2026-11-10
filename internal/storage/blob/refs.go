// Blob reference scans over mail metadata and the outbound queue.
package blob

import (
	"context"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

const (
	queueAccountID     uint32 = 0
	queueMsgCollection byte   = 1
)

// ReferencedHashes returns every blob hash still pointed at by mail or queue rows.
func ReferencedHashes(ctx context.Context, store storage.Store) (map[[storage.Blake3DigestLen]byte]struct{}, error) {
	refs := make(map[[storage.Blake3DigestLen]byte]struct{})
	err := scanMailHashes(ctx, store, func(h [storage.Blake3DigestLen]byte) error {
		refs[h] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = scanQueueHashes(ctx, store, func(h [storage.Blake3DigestLen]byte) error {
		refs[h] = struct{}{}
		return nil
	})
	return refs, err
}

func scanMailHashes(ctx context.Context, store storage.Store, fn func([storage.Blake3DigestLen]byte) error) error {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceMail, 0, 0, byte(storage.CollectionEmail), 6)
	to := storage.AppendKey(nil, storage.SubspaceMail, ^uint32(0), ^uint32(0), byte(storage.CollectionEmail), nil)
	return store.Iterate(ctx, from, to, func(k, v []byte) error {
		parts, err := storage.DecodeKey(k)
		if err != nil {
			return err
		}
		if parts.Collection != byte(storage.CollectionEmail) || len(parts.Suffix) > 0 {
			return nil
		}
		var meta storage.EmailMeta
		if err := storage.UnmarshalPersist(v, &meta); err != nil {
			return err
		}
		if !meta.HasBlob() {
			return nil
		}
		return fn(meta.BlobHash)
	})
}

func scanQueueHashes(ctx context.Context, store storage.Store, fn func([storage.Blake3DigestLen]byte) error) error {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceQueue, queueAccountID, 0, queueMsgCollection, 6)
	to := storage.AppendKey(nil, storage.SubspaceQueue, queueAccountID, ^uint32(0), queueMsgCollection, nil)
	return store.Iterate(ctx, from, to, func(_, v []byte) error {
		var msg storage.QueueMessage
		if err := storage.UnmarshalPersist(v, &msg); err != nil {
			return err
		}
		if !msg.HasBlob() {
			return nil
		}
		return fn(msg.BlobHash)
	})
}
