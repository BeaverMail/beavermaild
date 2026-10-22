// Account storage quotas (RFC 2087) with usage counters in SubspaceLookup.
package mail

import (
	"context"
	"errors"
	"fmt"

	"github.com/BeaverMail/beaver/internal/storage"
)

// ErrOverQuota is returned when a message would exceed account storage limits.
var ErrOverQuota = errors.New("mail: over quota")

// QuotaDefaults applies to new accounts when no per-account limits are stored.
type QuotaDefaults struct {
	StorageBytes uint64
	Messages     uint32
}

// QuotaStatus is current usage and limits for one account.
type QuotaStatus struct {
	Root          string
	StorageUsed   uint64
	StorageLimit  uint64 // 0 = unlimited
	MessagesUsed  uint32
	MessagesLimit uint32 // 0 = unlimited
}

// QuotaRoot is the IMAP quotaroot for personal mailboxes on this server.
const QuotaRoot = ""

// quotaRecord persists limits and cached usage for one account.
type quotaRecord struct {
	StorageLimit uint64 `msgpack:"sl,omitempty"`
	MessageLimit uint32 `msgpack:"ml,omitempty"`
	StorageUsed  uint64 `msgpack:"su,omitempty"`
	MessagesUsed uint32 `msgpack:"mu,omitempty"`
}

// SetQuotaDefaults configures default limits for accounts without stored limits.
func (ib *Inbox) SetQuotaDefaults(d QuotaDefaults) {
	ib.quotaDefault = d
}

// AccountQuotaDefaultsFunc returns per-account defaults (e.g. from domain hosting settings).
// ok=false keeps the process-wide SetQuotaDefaults values.
type AccountQuotaDefaultsFunc func(ctx context.Context, accountID uint32) (QuotaDefaults, bool)

// SetAccountQuotaDefaultsFunc overrides global defaults when first materializing a quota record.
func (ib *Inbox) SetAccountQuotaDefaultsFunc(fn AccountQuotaDefaultsFunc) {
	ib.accountQuotaFn = fn
}

// QuotaStatus returns RFC 2087 quota counters for accountID.
func (ib *Inbox) QuotaStatus(ctx context.Context, accountID uint32) (QuotaStatus, error) {
	rec, err := ib.loadQuotaRecord(ctx, accountID)
	if err != nil {
		return QuotaStatus{}, err
	}
	return QuotaStatus{
		Root:          QuotaRoot,
		StorageUsed:   rec.StorageUsed,
		StorageLimit:  rec.StorageLimit,
		MessagesUsed:  rec.MessagesUsed,
		MessagesLimit: rec.MessageLimit,
	}, nil
}

// SetQuotaLimits overrides the stored limits for accountID (0 = unlimited); nil keeps the current value.
func (ib *Inbox) SetQuotaLimits(ctx context.Context, accountID uint32, storageBytes *uint64, messages *uint32) error {
	ib.quotaMu.Lock()
	defer ib.quotaMu.Unlock()
	rec, err := ib.loadQuotaRecord(ctx, accountID)
	if err != nil {
		return err
	}
	if storageBytes != nil {
		rec.StorageLimit = *storageBytes
	}
	if messages != nil {
		rec.MessageLimit = *messages
	}
	return ib.saveQuotaRecord(ctx, accountID, rec)
}

func (ib *Inbox) checkQuota(ctx context.Context, accountID uint32, addBytes uint64, addMessages uint32) error {
	rec, err := ib.loadQuotaRecord(ctx, accountID)
	if err != nil {
		return err
	}
	if rec.MessageLimit > 0 && uint64(rec.MessagesUsed)+uint64(addMessages) > uint64(rec.MessageLimit) {
		return ErrOverQuota
	}
	if rec.StorageLimit > 0 && rec.StorageUsed+addBytes > rec.StorageLimit {
		return ErrOverQuota
	}
	return nil
}

func (ib *Inbox) addQuotaUsage(ctx context.Context, accountID uint32, addBytes uint64, addMessages uint32) error {
	ib.quotaMu.Lock()
	defer ib.quotaMu.Unlock()
	rec, err := ib.loadQuotaRecord(ctx, accountID)
	if err != nil {
		return err
	}
	rec.StorageUsed += addBytes
	rec.MessagesUsed += addMessages
	return ib.saveQuotaRecord(ctx, accountID, rec)
}

func (ib *Inbox) subQuotaUsage(ctx context.Context, accountID uint32, subBytes uint64, subMessages uint32) error {
	ib.quotaMu.Lock()
	defer ib.quotaMu.Unlock()
	rec, err := ib.loadQuotaRecord(ctx, accountID)
	if err != nil {
		return err
	}
	if rec.StorageUsed >= subBytes {
		rec.StorageUsed -= subBytes
	} else {
		rec.StorageUsed = 0
	}
	if rec.MessagesUsed >= subMessages {
		rec.MessagesUsed -= subMessages
	} else {
		rec.MessagesUsed = 0
	}
	return ib.saveQuotaRecord(ctx, accountID, rec)
}

func (ib *Inbox) quotaLookupKey(accountID uint32) []byte {
	return storage.AppendKey(nil, storage.SubspaceLookup, 0, 0, 0,
		fmt.Appendf(nil, "meta/quota/%d", accountID))
}

func (ib *Inbox) loadQuotaRecord(ctx context.Context, accountID uint32) (quotaRecord, error) {
	key := ib.quotaLookupKey(accountID)
	wire, err := ib.store.Get(ctx, key)
	if err == nil {
		var rec quotaRecord
		if err := storage.UnmarshalPersist(wire, &rec); err != nil {
			return quotaRecord{}, err
		}
		return rec, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return quotaRecord{}, err
	}
	usedStorage, usedMessages, err := ib.recomputeQuotaUsage(ctx, accountID)
	if err != nil {
		return quotaRecord{}, err
	}
	defaults := ib.quotaDefault
	if ib.accountQuotaFn != nil {
		if d, ok := ib.accountQuotaFn(ctx, accountID); ok {
			if d.StorageBytes > 0 {
				defaults.StorageBytes = d.StorageBytes
			}
			if d.Messages > 0 {
				defaults.Messages = d.Messages
			}
		}
	}
	rec := quotaRecord{
		StorageLimit: defaults.StorageBytes,
		MessageLimit: defaults.Messages,
		StorageUsed:  usedStorage,
		MessagesUsed: usedMessages,
	}
	if err := ib.saveQuotaRecord(ctx, accountID, rec); err != nil {
		return quotaRecord{}, err
	}
	return rec, nil
}

func (ib *Inbox) saveQuotaRecord(ctx context.Context, accountID uint32, rec quotaRecord) error {
	wire, err := storage.MarshalPersist(nil, 1, rec)
	if err != nil {
		return err
	}
	batch := storage.NewBatch().WithAccount(0)
	suffix := storage.BatchSuffix(0, 0, fmt.Appendf(nil, "meta/quota/%d", accountID))
	if err := batch.Set(storage.SubspaceLookup, suffix, wire); err != nil {
		return err
	}
	return ib.store.Commit(ctx, batch)
}

func (ib *Inbox) recomputeQuotaUsage(ctx context.Context, accountID uint32) (storageUsed uint64, messagesUsed uint32, err error) {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceMail, accountID, 0, byte(storage.CollectionEmail), 6)
	to := storage.AppendKey(nil, storage.SubspaceMail, accountID, ^uint32(0), byte(storage.CollectionEmail), nil)
	err = ib.store.Iterate(ctx, from, to, func(k, v []byte) error {
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
		storageUsed += uint64(meta.Size)
		messagesUsed++
		return nil
	})
	return storageUsed, messagesUsed, err
}
