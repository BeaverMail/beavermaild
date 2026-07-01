// Blob reference scans over mail metadata and the outbound queue.
package blob

import (
	"context"
	"errors"

	"github.com/BeaverMail/beaver/internal/storage"
)

const (
	queueAccountID     uint32 = 0
	queueMsgCollection byte   = 1
)

var errBlobReferenced = errors.New("blob: referenced")

// StillReferenced reports whether hash is used by any mail message or queue entry.
func StillReferenced(ctx context.Context, store storage.Store, hash [storage.Blake3DigestLen]byte) (bool, error) {
	if hash == ([storage.Blake3DigestLen]byte{}) {
		return false, nil
	}
	err := scanMailHashes(ctx, store, func(h [storage.Blake3DigestLen]byte) error {
		if h == hash {
			return errBlobReferenced
		}
		return nil
	})
	if errors.Is(err, errBlobReferenced) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	err = scanQueueHashes(ctx, store, func(h [storage.Blake3DigestLen]byte) error {
		if h == hash {
			return errBlobReferenced
		}
		return nil
	})
	if errors.Is(err, errBlobReferenced) {
		return true, nil
	}
	return false, err
}

// RemoveIfUnreferenced deletes the blob file when no mail or queue row references hash.
func RemoveIfUnreferenced(ctx context.Context, store storage.Store, fs *FS, hash [storage.Blake3DigestLen]byte) error {
	if hash == ([storage.Blake3DigestLen]byte{}) {
		return nil
	}
	ref, err := StillReferenced(ctx, store, hash)
	if err != nil {
		return err
	}
	if ref {
		return nil
	}
	return fs.Remove(hash)
}

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
