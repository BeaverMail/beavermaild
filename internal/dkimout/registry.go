package dkimout

import (
	"strings"
	"sync"
)

// Registry signs with a per-domain signer, falling back to a global signer.
type Registry struct {
	mu      sync.RWMutex
	byDom   map[string]*Signer // domain name → signer
	fallback *Signer
}

// NewRegistry returns an empty multi-domain DKIM registry.
func NewRegistry(fallback *Signer) *Registry {
	return &Registry{byDom: make(map[string]*Signer), fallback: fallback}
}

// Set registers or replaces the signer for domain.
func (r *Registry) Set(domain string, s *Signer) {
	if r == nil {
		return
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	r.mu.Lock()
	defer r.mu.Unlock()
	if s == nil {
		delete(r.byDom, domain)
		return
	}
	r.byDom[domain] = s
}

// Sign implements mail.DKIMSigner using the return-path domain's key.
func (r *Registry) Sign(returnPath string, raw []byte) ([]byte, error) {
	if r == nil {
		return raw, nil
	}
	dom, err := domainFromAddress(returnPath)
	if err != nil {
		if r.fallback != nil {
			return r.fallback.Sign(returnPath, raw)
		}
		return raw, nil
	}
	r.mu.RLock()
	s := r.byDom[dom]
	fb := r.fallback
	r.mu.RUnlock()
	if s != nil {
		return s.Sign(returnPath, raw)
	}
	if fb != nil {
		return fb.Sign(returnPath, raw)
	}
	return raw, nil
}

// LoadDomain adds a signer from path for domain with selector.
func (r *Registry) LoadDomain(domain, selector, keyPath string) error {
	s, err := New(Config{Selector: selector, Domain: domain, KeyPath: keyPath})
	if err != nil {
		return err
	}
	r.Set(domain, s)
	return nil
}
