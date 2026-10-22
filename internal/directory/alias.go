// Local aliases: <local>@<domain> delivered to existing accounts of the same tenant.
package directory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/BeaverMail/beaver/internal/storage"
)

// MaxAliasTargets bounds the copies one alias can fan out to.
const MaxAliasTargets = 50

// AliasView is an alias with its targets as addresses (targets whose account is gone are left out).
type AliasView struct {
	Email     string
	LocalPart string
	Domain    storage.Domain
	Targets   []string
}

func aliasSuffix(domainID uint32, localPart string) []byte {
	return fmt.Appendf(nil, "alias/%d/%s", domainID, localPart)
}

func aliasKey(domainID uint32, localPart string) []byte {
	return storage.AppendKey(nil, storage.SubspaceLookup, systemAccountID, 0, 0, aliasSuffix(domainID, localPart))
}

func (d *Local) getAlias(ctx context.Context, domainID uint32, localPart string) (storage.Alias, error) {
	var a storage.Alias
	if err := d.getRecord(ctx, aliasKey(domainID, localPart), &a); err != nil {
		return storage.Alias{}, err
	}
	return a, nil
}

// aliasExists reports whether localPart is an alias on domainID.
func (d *Local) aliasExists(ctx context.Context, domainID uint32, localPart string) (bool, error) {
	_, err := d.getAlias(ctx, domainID, localPart)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// aliasTargetIDs resolves target addresses to account ids, all in tenantID.
func (d *Local) aliasTargetIDs(ctx context.Context, tenantID uint32, targets []string) ([]uint32, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("directory: alias needs at least one target")
	}
	if len(targets) > MaxAliasTargets {
		return nil, fmt.Errorf("directory: alias has more than %d targets", MaxAliasTargets)
	}
	ids := make([]uint32, 0, len(targets))
	for _, t := range targets {
		acc, _, err := d.lookupAccount(ctx, t)
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("directory: alias target %q is not a mailbox on this server", t)
		}
		if err != nil {
			return nil, err
		}
		if acc.TenantID != tenantID {
			return nil, fmt.Errorf("directory: alias target %q belongs to another tenant", t)
		}
		if !slices.Contains(ids, acc.ID) {
			ids = append(ids, acc.ID)
		}
	}
	return ids, nil
}

func (d *Local) putAlias(ctx context.Context, domainID uint32, a storage.Alias, mustBeNew bool) error {
	wire, err := storage.MarshalPersist(nil, 1, a)
	if err != nil {
		return err
	}
	batch := storage.NewBatch().WithAccount(systemAccountID)
	suffix := storage.BatchSuffix(0, 0, aliasSuffix(domainID, a.LocalPart))
	if mustBeNew {
		if err := batch.Assert(storage.SubspaceLookup, suffix, nil); err != nil {
			return err
		}
	}
	if err := batch.Set(storage.SubspaceLookup, suffix, wire); err != nil {
		return err
	}
	if err := d.store.Commit(ctx, batch); err != nil {
		if errors.Is(err, storage.ErrCASConflict) {
			return ErrExists
		}
		return err
	}
	return nil
}

// CreateAlias adds localPart@domainName delivering to targets (existing mailboxes of the same tenant).
// ErrExists when a mailbox or alias already uses the address.
func (d *Local) CreateAlias(ctx context.Context, domainName, localPart string, targets []string) (AliasView, error) {
	dom, err := d.LookupDomain(ctx, domainName)
	if err != nil {
		return AliasView{}, err
	}
	localPart = normalizeLocalPart(localPart)
	if localPart == "" || strings.ContainsAny(localPart, "@/ ") {
		return AliasView{}, fmt.Errorf("directory: invalid alias local part")
	}
	if _, ok := ReportLocalParts[localPart]; ok {
		return AliasView{}, fmt.Errorf("directory: local part %q is reserved for %s reports", localPart, ReportLocalParts[localPart])
	}
	if _, err := d.lookupAccountID(ctx, localPart+"@"+dom.Name); err == nil {
		return AliasView{}, ErrExists
	} else if !errors.Is(err, ErrNotFound) {
		return AliasView{}, err
	}
	ids, err := d.aliasTargetIDs(ctx, dom.TenantID, targets)
	if err != nil {
		return AliasView{}, err
	}
	a := storage.Alias{LocalPart: localPart, Targets: ids}
	if err := d.putAlias(ctx, dom.ID, a, true); err != nil {
		return AliasView{}, err
	}
	return d.aliasView(ctx, dom, a), nil
}

// SetAliasTargets replaces the targets of an existing alias.
func (d *Local) SetAliasTargets(ctx context.Context, email string, targets []string) (AliasView, error) {
	local, domainName, err := splitEmail(email)
	if err != nil {
		return AliasView{}, err
	}
	dom, err := d.LookupDomain(ctx, domainName)
	if err != nil {
		return AliasView{}, err
	}
	a, err := d.getAlias(ctx, dom.ID, local)
	if err != nil {
		return AliasView{}, err
	}
	if a.Targets, err = d.aliasTargetIDs(ctx, dom.TenantID, targets); err != nil {
		return AliasView{}, err
	}
	if err := d.putAlias(ctx, dom.ID, a, false); err != nil {
		return AliasView{}, err
	}
	return d.aliasView(ctx, dom, a), nil
}

// DeleteAlias removes an alias; ErrNotFound when it does not exist.
func (d *Local) DeleteAlias(ctx context.Context, email string) error {
	local, domainName, err := splitEmail(email)
	if err != nil {
		return err
	}
	dom, err := d.LookupDomain(ctx, domainName)
	if err != nil {
		return err
	}
	if _, err := d.getAlias(ctx, dom.ID, local); err != nil {
		return err
	}
	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := batch.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, aliasSuffix(dom.ID, local))); err != nil {
		return err
	}
	return d.store.Commit(ctx, batch)
}

// ListAliases returns the aliases of domainName sorted by local part.
func (d *Local) ListAliases(ctx context.Context, domainName string) ([]AliasView, storage.Domain, error) {
	dom, err := d.LookupDomain(ctx, domainName)
	if err != nil {
		return nil, storage.Domain{}, err
	}
	aliases, err := d.domainAliases(ctx, dom.ID)
	if err != nil {
		return nil, storage.Domain{}, err
	}
	out := make([]AliasView, len(aliases))
	for i, a := range aliases {
		out[i] = d.aliasView(ctx, dom, a)
	}
	return out, dom, nil
}

func (d *Local) domainAliases(ctx context.Context, domainID uint32) ([]storage.Alias, error) {
	prefix := fmt.Appendf(nil, "alias/%d/", domainID)
	from := storage.AppendKey(nil, storage.SubspaceLookup, systemAccountID, 0, 0, prefix)
	to := storage.AppendKey(nil, storage.SubspaceLookup, systemAccountID, 0, 0, append(prefix, 0xff))
	var out []storage.Alias
	err := d.store.Iterate(ctx, from, to, func(_, v []byte) error {
		var a storage.Alias
		if err := storage.UnmarshalPersist(v, &a); err != nil {
			return err
		}
		out = append(out, a)
		return nil
	})
	return out, err
}

// ResolveAlias returns the existing accounts an alias address delivers to (ErrNotFound when the
// address is not an alias). Targets deleted since the alias was set are skipped.
func (d *Local) ResolveAlias(ctx context.Context, email string) ([]storage.Account, error) {
	local, domainName, err := splitEmail(email)
	if err != nil {
		return nil, err
	}
	dom, err := d.LookupDomain(ctx, domainName)
	if err != nil {
		return nil, err
	}
	a, err := d.getAlias(ctx, dom.ID, local)
	if err != nil {
		return nil, err
	}
	var out []storage.Account
	for _, id := range a.Targets {
		acc, err := d.getAccount(ctx, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, acc)
	}
	return out, nil
}

func (d *Local) aliasView(ctx context.Context, dom storage.Domain, a storage.Alias) AliasView {
	v := AliasView{Email: a.LocalPart + "@" + dom.Name, LocalPart: a.LocalPart, Domain: dom, Targets: []string{}}
	for _, id := range a.Targets {
		acc, err := d.getAccount(ctx, id)
		if err != nil {
			continue
		}
		accDom, err := d.getDomain(ctx, acc.DomainID)
		if err != nil {
			continue
		}
		v.Targets = append(v.Targets, acc.LocalPart+"@"+accDom.Name)
	}
	return v
}

// deleteDomainAliases queues removal of every alias of domainID.
func (d *Local) deleteDomainAliases(ctx context.Context, batch *storage.Batch, domainID uint32) error {
	aliases, err := d.domainAliases(ctx, domainID)
	if err != nil {
		return err
	}
	for _, a := range aliases {
		if err := batch.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, aliasSuffix(domainID, a.LocalPart))); err != nil {
			return err
		}
	}
	return nil
}
