// Account mail purge: KV wipe plus reference-safe blob filesystem cleanup.
package directory

import (
	"context"

	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
)

// purgeAccountResult reports KV and blob cleanup for one account.
type purgeAccountResult struct {
	messagesRemoved uint32
	blobsRemoved    uint32
}

// purgeAccountMail deletes all mail metadata for accountID and removes blob files
// that are no longer referenced by any account mail or the outbound queue.
func purgeAccountMail(ctx context.Context, store storage.Store, blobs *blob.FS, accountID uint32) (purgeAccountResult, error) {
	hashes, msgCount, err := collectAccountBlobHashes(ctx, store, accountID)
	if err != nil {
		return purgeAccountResult{}, err
	}
	if err := deleteMailKVForAccount(ctx, store, accountID); err != nil {
		return purgeAccountResult{}, err
	}
	stillReferenced, err := blob.ReferencedHashes(ctx, store)
	if err != nil {
		return purgeAccountResult{}, err
	}
	var blobsRemoved uint32
	for h := range hashes {
		if _, ok := stillReferenced[h]; ok {
			continue
		}
		if err := blobs.Remove(h); err != nil {
			return purgeAccountResult{}, err
		}
		blobsRemoved++
	}
	return purgeAccountResult{
		messagesRemoved: msgCount,
		blobsRemoved:    blobsRemoved,
	}, nil
}

// collectAccountBlobHashes returns unique blob hashes and email count for accountID.
func collectAccountBlobHashes(ctx context.Context, store storage.Store, accountID uint32) (map[[storage.Blake3DigestLen]byte]struct{}, uint32, error) {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceMail, accountID, 0, byte(storage.CollectionEmail), 6)
	to := storage.AppendKey(nil, storage.SubspaceMail, accountID, ^uint32(0), byte(storage.CollectionEmail), nil)

	hashes := make(map[[storage.Blake3DigestLen]byte]struct{})
	var msgCount uint32
	err := store.Iterate(ctx, from, to, func(k, v []byte) error {
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
		msgCount++
		if meta.HasBlob() {
			hashes[meta.BlobHash] = struct{}{}
		}
		return nil
	})
	return hashes, msgCount, err
}

// deleteMailKVForAccount removes all SubspaceMail and mailbox index keys for accountID.
func deleteMailKVForAccount(ctx context.Context, store storage.Store, accountID uint32) error {
	if err := deleteSubspaceKeysForAccount(ctx, store, accountID, storage.SubspaceMail); err != nil {
		return err
	}
	return deleteSubspaceKeysForAccount(ctx, store, accountID, storage.SubspaceIndex)
}

func deleteSubspaceKeysForAccount(ctx context.Context, store storage.Store, accountID uint32, subspace byte) error {
	from := storage.AppendKeyPrefix(nil, subspace, accountID, 0, 0, 5)
	to := storage.AppendKey(nil, subspace, accountID, ^uint32(0), 0xff, nil)

	batch := storage.NewBatch().WithAccount(accountID)
	err := store.Iterate(ctx, from, to, func(k, _ []byte) error {
		parts, err := storage.DecodeKey(k)
		if err != nil {
			return err
		}
		suffix := storage.BatchSuffix(parts.Collection, parts.DocumentID, parts.Suffix)
		return batch.Delete(parts.Subspace, suffix)
	})
	if err != nil {
		return err
	}
	if len(batch.Ops()) == 0 {
		return nil
	}
	return store.Commit(ctx, batch)
}
