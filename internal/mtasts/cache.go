// MTA-STS policy cache persistence and proactive refresh (RFC 8461 3.3, 10.2).
package mtasts

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

const (
	firstRefresh    = 5 * time.Minute // after startup, once the network is up
	refreshInterval = 24 * time.Hour  // RFC 8461 3.3: "a suggested refresh frequency is once per day"
)

// diskEntry is one cached policy in the cache file.
type diskEntry struct {
	Policy  *Policy   `json:"policy"`
	Fetched time.Time `json:"fetched"`
}

// WithLogger sets where policy refresh failures are reported.
func (r *Resolver) WithLogger(log *slog.Logger) *Resolver {
	r.log = log
	return r
}

// LoadCache makes path the cache file and loads the unexpired policies in it. Without it the cache
// is lost on restart, and every domain can be downgraded until its policy is fetched again (10.2).
// A missing file is an empty cache. Entries fetched "in the future" (the clock went back) are dropped:
// they would outlive their max_age.
func (r *Resolver) LoadCache(path string) error {
	r.path = path
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var entries map[string]diskEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for domain, e := range entries {
		if len(r.byDomain) >= maxCachedPolicies {
			break
		}
		p := e.Policy
		if p == nil || normalizeHost(domain) != domain || p.Domain != domain || p.MaxAge < 0 ||
			p.Mode != ModeNone && p.Mode != ModeTesting && p.Mode != ModeEnforce ||
			e.Fetched.After(r.now()) || r.now().Sub(e.Fetched) >= p.MaxAge {
			continue
		}
		r.byDomain[domain] = &cacheEntry{policy: p, fetched: e.Fetched}
	}
	return nil
}

// save writes the unexpired cache entries to the cache file (temp file + rename).
func (r *Resolver) save() {
	if r.path == "" {
		return
	}
	r.saveMu.Lock()
	defer r.saveMu.Unlock()
	r.mu.Lock()
	entries := make(map[string]diskEntry, len(r.byDomain))
	for domain, ent := range r.byDomain {
		if r.now().Sub(ent.fetched) < ent.policy.MaxAge {
			entries[domain] = diskEntry{Policy: ent.policy, Fetched: ent.fetched}
		}
	}
	r.mu.Unlock()
	data, err := json.Marshal(entries)
	if err == nil {
		err = writeFileAtomic(r.path, data)
	}
	if err != nil && r.log != nil {
		r.log.Warn("mta-sts: cannot save policy cache", "path", r.path, "err", err)
	}
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path) // CreateTemp makes it 0600
}

// Run refreshes the cached policies shortly after startup and then daily, until ctx ends.
func (r *Resolver) Run(ctx context.Context) {
	t := time.NewTimer(firstRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r.refresh(ctx)
		t.Reset(refreshInterval)
	}
}

// refresh fetches the live policy of every cached domain, whatever the TXT record says, so an attacker
// must block discovery for a policy's whole lifetime to drop it (RFC 8461 10.2). A failed refresh is
// logged, except for mode none (8.3: a clean opt-out), long before the policy expires.
func (r *Resolver) refresh(ctx context.Context) {
	r.mu.Lock()
	cached := make(map[string]*cacheEntry, len(r.byDomain))
	for domain, ent := range r.byDomain {
		if r.now().Sub(ent.fetched) >= ent.policy.MaxAge {
			delete(r.byDomain, domain)
			continue
		}
		cached[domain] = ent
	}
	r.mu.Unlock()
	for domain, ent := range cached {
		if ctx.Err() != nil {
			return
		}
		id := ent.policy.PolicyID
		if records, err := r.lookup(ctx, "_mta-sts."+domain); err == nil {
			if live, ok := parseTXTRecord(records); ok {
				id = live
			}
		}
		if _, err := r.fetchParsed(ctx, domain, id); err != nil && ent.policy.Mode != ModeNone && r.log != nil {
			r.log.Warn("mta-sts: policy refresh failed", "domain", domain, "mode", ent.policy.Mode,
				"expires", ent.fetched.Add(ent.policy.MaxAge), "err", err)
		}
	}
	r.save()
}
