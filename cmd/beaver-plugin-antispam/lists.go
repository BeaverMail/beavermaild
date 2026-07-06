// Lookup lists: spam traps, trusted domains, URL redirectors (Phase 7).
package main

import (
	"strings"
	"sync"
)

type lookupLists struct {
	mu              sync.RWMutex
	spamTraps       map[string]struct{}
	trustedDomains  map[string]struct{}
	urlRedirectors  map[string]struct{}
	badExtensions   map[string]struct{}
}

func newLookupLists() *lookupLists {
	return &lookupLists{
		spamTraps:      make(map[string]struct{}),
		trustedDomains: make(map[string]struct{}),
		urlRedirectors: make(map[string]struct{}),
		badExtensions:  make(map[string]struct{}),
	}
}

func (l *lookupLists) reload(cfg pluginConfig, dataDir string) {
	base := antispamDir(dataDir)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.spamTraps = toSet(loadListFiles(base, cfg.Lists.SpamTraps))
	l.trustedDomains = toSet(loadListFiles(base, cfg.Lists.TrustedDomains))
	l.urlRedirectors = toSet(loadListFiles(base, cfg.Lists.URLRedirectors))
	l.badExtensions = toSet(cfg.Lists.BadExtensions)
	for _, e := range []string{".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js"} {
		l.badExtensions[e] = struct{}{}
	}
}

func toSet(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		it = strings.ToLower(strings.TrimSpace(it))
		if it != "" {
			m[it] = struct{}{}
		}
	}
	return m
}

func (l *lookupLists) isSpamTrap(addr string) bool {
	addr = strings.ToLower(strings.Trim(addr, "<>"))
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.spamTraps[addr]
	return ok
}

func (l *lookupLists) isTrustedDomain(host string) bool {
	sld := domainSLD(host)
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.trustedDomains[sld]
	return ok
}

func (l *lookupLists) isURLRedirector(host string) bool {
	sld := domainSLD(host)
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.urlRedirectors[sld]
	return ok
}

func (l *lookupLists) isBadExtension(name string) bool {
	name = strings.ToLower(name)
	l.mu.RLock()
	defer l.mu.RUnlock()
	for ext := range l.badExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
