// Account storage quotas (RFC 9208) with usage counters in SubspaceLookup.
package mail

import (
	"context"
	"errors"
	"fmt"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// ErrOverQuota is returned when a message would exceed account storage limits.
var ErrOverQuota = errors.New("mail: over quota")

// QuotaDefaults applies to every account without a limit of its own.
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
	// StorageLimitSet and MessagesLimitSet report a limit set on the account itself; otherwise the
	// limit is the domain's, or the server default.
	StorageLimitSet  bool
	MessagesLimitSet bool
}

// QuotaRoot is the IMAP quotaroot for personal mailboxes on this server.
const QuotaRoot = ""

// quotaRecord persists limits and cached usage for one account.
type quotaRecord struct {
	StorageLimit uint64 `msgpack:"sl,omitempty"`
	MessageLimit uint32 `msgpack:"ml,omitempty"`
	StorageUsed  uint64 `msgpack:"su,omitempty"`
	MessagesUsed uint32 `msgpack:"mu,omitempty"`
	// StorageSet and MessageSet mark a limit set on the account; an unset one follows the domain,
	// then the server default, as they are at the time of each check.
	StorageSet bool `msgpack:"ss,omitempty"`
	MessageSet bool `msgpack:"ms,omitempty"`
}

// QuotaDefaults returns the server-wide limits set with SetQuotaDefaults (0 = unlimited).
func (ib *Inbox) QuotaDefaults() QuotaDefaults { return ib.quotaDefault }

// SetQuotaDefaults configures default limits for accounts without stored limits.
func (ib *Inbox) SetQuotaDefaults(d QuotaDefaults) {
	ib.quotaDefault = d
}

// AccountQuotaDefaultsFunc returns the defaults of the account's domain; a zero value or ok=false
// keeps the server-wide SetQuotaDefaults value.
type AccountQuotaDefaultsFunc func(ctx context.Context, accountID uint32) (storageBytes uint64, messages uint32, ok bool)

// SetAccountQuotaDefaultsFunc sets where domain defaults come from; they are read at every check.
func (ib *Inbox) SetAccountQuotaDefaultsFunc(fn AccountQuotaDefaultsFunc) {
	ib.accountQuotaFn = fn
}

// TenantStorageCapFunc returns the storage cap shared by accountID's tenant and the ids of all
// accounts in it; limit 0 means no tenant cap.
type TenantStorageCapFunc func(ctx context.Context, accountID uint32) (limit uint64, accountIDs []uint32, err error)

// SetTenantStorageCapFunc enables the tenant-wide storage cap on delivery, APPEND, and copy.
func (ib *Inbox) SetTenantStorageCapFunc(fn TenantStorageCapFunc) {
	ib.tenantCapFn = fn
}

// StorageUsed sums the stored bytes of accountIDs.
func (ib *Inbox) StorageUsed(ctx context.Context, accountIDs []uint32) (uint64, error) {
	var total uint64
	for _, id := range accountIDs {
		st, err := ib.QuotaStatus(ctx, id)
		if err != nil {
			return 0, err
		}
		total += st.StorageUsed
	}
	return total, nil
}

// QuotaStatus returns RFC 2087 quota counters for accountID.
func (ib *Inbox) QuotaStatus(ctx context.Context, accountID uint32) (QuotaStatus, error) {
	rec, err := ib.loadQuotaRecord(ctx, accountID)
	if err != nil {
		return QuotaStatus{}, err
	}
	storageLimit, messageLimit := ib.quotaLimits(ctx, accountID, rec)
	return QuotaStatus{
		Root:             QuotaRoot,
		StorageUsed:      rec.StorageUsed,
		StorageLimit:     storageLimit,
		MessagesUsed:     rec.MessagesUsed,
		MessagesLimit:    messageLimit,
		StorageLimitSet:  rec.StorageSet,
		MessagesLimitSet: rec.MessageSet,
	}, nil
}

// SetQuotaLimits sets limits on accountID itself (0 = unlimited); nil keeps the current value.
func (ib *Inbox) SetQuotaLimits(ctx context.Context, accountID uint32, storageBytes *uint64, messages *uint32) error {
	return ib.editQuotaRecord(ctx, accountID, func(rec *quotaRecord) {
		if storageBytes != nil {
			rec.StorageLimit, rec.StorageSet = *storageBytes, true
		}
		if messages != nil {
			rec.MessageLimit, rec.MessageSet = *messages, true
		}
	})
}

// ResetQuotaLimits drops the limits set on accountID, so it follows the domain and server defaults.
func (ib *Inbox) ResetQuotaLimits(ctx context.Context, accountID uint32, storageLimit, messageLimit bool) error {
	return ib.editQuotaRecord(ctx, accountID, func(rec *quotaRecord) {
		if storageLimit {
			rec.StorageLimit, rec.StorageSet = 0, false
		}
		if messageLimit {
			rec.MessageLimit, rec.MessageSet = 0, false
		}
	})
}

func (ib *Inbox) editQuotaRecord(ctx context.Context, accountID uint32, edit func(*quotaRecord)) error {
	return ib.update(ctx, accountID, func(t *txn) error {
		key := ib.quotaLookupKey(accountID)
		var rec quotaRecord
		err := t.getPersist(key, &rec)
		if errors.Is(err, storage.ErrNotFound) {
			rec, err = ib.newQuotaRecord(t.ctx, accountID)
		}
		if err != nil {
			return err
		}
		edit(&rec)
		return t.setPersist(key, rec)
	})
}

// quotaDefaults is the limit an account without its own gets: the domain's, else the server's.
func (ib *Inbox) quotaDefaults(ctx context.Context, accountID uint32) QuotaDefaults {
	d := ib.quotaDefault
	if ib.accountQuotaFn != nil {
		if sb, msgs, ok := ib.accountQuotaFn(ctx, accountID); ok {
			if sb > 0 {
				d.StorageBytes = sb
			}
			if msgs > 0 {
				d.Messages = msgs
			}
		}
	}
	return d
}

// quotaLimits returns the limits in force for accountID (0 = unlimited).
func (ib *Inbox) quotaLimits(ctx context.Context, accountID uint32, rec quotaRecord) (storageBytes uint64, messages uint32) {
	d := ib.quotaDefaults(ctx, accountID)
	if rec.StorageSet {
		d.StorageBytes = rec.StorageLimit
	}
	if rec.MessageSet {
		d.Messages = rec.MessageLimit
	}
	return d.StorageBytes, d.Messages
}

func (ib *Inbox) checkQuota(ctx context.Context, accountID uint32, addBytes uint64, addMessages uint32) error {
	rec, err := ib.loadQuotaRecord(ctx, accountID)
	if err != nil {
		return err
	}
	storageLimit, messageLimit := ib.quotaLimits(ctx, accountID, rec)
	if messageLimit > 0 && uint64(rec.MessagesUsed)+uint64(addMessages) > uint64(messageLimit) {
		return ErrOverQuota
	}
	if storageLimit > 0 && rec.StorageUsed+addBytes > storageLimit {
		return ErrOverQuota
	}
	// shortcut: the tenant cap spans accounts, so it is checked here only, outside the store
	// transaction; concurrent stores in one tenant all pass it (each account's own limit still
	// holds). Move it into a tenant-wide transaction if tenants run close to their cap.
	if ib.tenantCapFn == nil || addBytes == 0 {
		return nil
	}
	limit, ids, err := ib.tenantCapFn(ctx, accountID)
	if err != nil || limit == 0 {
		return err
	}
	used, err := ib.StorageUsed(ctx, ids)
	if err != nil {
		return err
	}
	if used+addBytes > limit {
		return ErrOverQuota
	}
	return nil
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
	// Materialize once; addQuota on a missing record keeps the winner of a concurrent create.
	var rec quotaRecord
	err = ib.update(ctx, accountID, func(t *txn) error {
		err := t.getPersist(key, &rec)
		if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		if rec, err = ib.newQuotaRecord(t.ctx, accountID); err != nil {
			return err
		}
		return t.setPersist(key, rec)
	})
	return rec, err
}

// newQuotaRecord builds the initial record: no limits of its own, usage recomputed from stored messages.
func (ib *Inbox) newQuotaRecord(ctx context.Context, accountID uint32) (quotaRecord, error) {
	usedStorage, usedMessages, err := ib.recomputeQuotaUsage(ctx, accountID)
	if err != nil {
		return quotaRecord{}, err
	}
	return quotaRecord{StorageUsed: usedStorage, MessagesUsed: usedMessages}, nil
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
