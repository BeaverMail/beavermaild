// IMAP mailbox subscription state (SUBSCRIBE / UNSUBSCRIBE).
package mail

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// mailboxSubscribed reports whether folder m appears in LSUB / LIST (SUBSCRIBED).
func mailboxSubscribed(m storage.Mailbox) bool {
	if m.SubSet && !m.Subscribed {
		return false
	}
	return true
}

// ListOrphanSubscriptions returns subscribed names whose folder was deleted: RFC 3501 6.3.6 keeps
// a subscription when its mailbox goes away, and LIST (SUBSCRIBED) shows it as \NonExistent.
func (ib *Inbox) ListOrphanSubscriptions(ctx context.Context, accountID uint32) ([]string, error) {
	wire, err := ib.store.Get(ctx, orphanSubscriptionsKey(accountID))
	if errors.Is(err, storage.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var subs []string
	return subs, storage.UnmarshalPersist(wire, &subs)
}

func orphanSubscriptionsKey(accountID uint32) []byte {
	return storage.AppendKey(nil, storage.SubspaceLookup, 0, 0, 0, fmt.Appendf(nil, "meta/subs/%d", accountID))
}

func (t *txn) orphanSubscriptions(accountID uint32) ([]string, error) {
	var subs []string
	if err := t.getPersist(orphanSubscriptionsKey(accountID), &subs); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	return subs, nil
}

func (t *txn) putOrphanSubscriptions(accountID uint32, subs []string) error {
	if len(subs) == 0 {
		t.del(orphanSubscriptionsKey(accountID))
		return nil
	}
	return t.setPersist(orphanSubscriptionsKey(accountID), subs)
}

// RepairImportedSubscriptions resets import-era folders that were stored unsubscribed.
func (ib *Inbox) RepairImportedSubscriptions(ctx context.Context, accountID uint32) error {
	return ib.repairMailboxSubscriptions(ctx, accountID)
}

// repairMailboxSubscriptions clears SubSet on import-era folders stored unsubscribed.
func (ib *Inbox) repairMailboxSubscriptions(ctx context.Context, accountID uint32) error {
	records, err := ib.listMailboxRecords(ctx, accountID)
	if err != nil {
		return err
	}
	return ib.update(ctx, accountID, func(t *txn) error {
		for _, r := range records {
			if r.ID <= DraftsMailboxID || !r.SubSet || r.Subscribed {
				continue
			}
			m, err := t.mailbox(accountID, r.ID)
			if errors.Is(err, storage.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			m.SubSet = false
			m.Subscribed = false
			if err := t.putMailbox(accountID, m); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetMailboxSubscribed updates the IMAP subscription flag for an existing folder. Unsubscribing
// a deleted folder's name drops its leftover subscription.
func (ib *Inbox) SetMailboxSubscribed(ctx context.Context, accountID uint32, imapName string, subscribed bool) error {
	mb, err := ib.ResolveMailbox(ctx, accountID, imapName)
	if errors.Is(err, storage.ErrNotFound) && !subscribed {
		name := stringsTrimMailboxName(imapName)
		return ib.update(ctx, accountID, func(t *txn) error {
			subs, err := t.orphanSubscriptions(accountID)
			if err != nil {
				return err
			}
			if !slices.Contains(subs, name) {
				return storage.ErrNotFound
			}
			return t.putOrphanSubscriptions(accountID, slices.DeleteFunc(subs, func(n string) bool { return n == name }))
		})
	}
	if err != nil {
		return err
	}
	return ib.update(ctx, accountID, func(t *txn) error {
		rec, err := t.mailbox(accountID, mb.ID)
		if err != nil {
			return err
		}
		rec.Subscribed = subscribed
		rec.SubSet = true
		return t.putMailbox(accountID, rec)
	})
}
