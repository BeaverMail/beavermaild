package dkimout

import (
	"sync"

	"github.com/BeaverMail/beavermaild/internal/dnsname"
)

// Registry signs with a per-domain signer, falling back to a global signer.
type Registry struct {
	mu       sync.RWMutex
	byDom    map[string]*Signer // domain name → signer
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
	domain = dnsname.ToASCII(domain)
	r.mu.Lock()
	defer r.mu.Unlock()
	if s == nil {
		delete(r.byDom, domain)
		return
	}
	r.byDom[domain] = s
}

// NewSigner implements mail.OutboundSigner with the return-path domain's key.
func (r *Registry) NewSigner(returnPath string, header []byte) (MessageSigner, error) {
	if r == nil {
		return nil, nil
	}
	r.mu.RLock()
	s := r.fallback
	if dom, err := domainFromAddress(returnPath); err == nil && r.byDom[dom] != nil {
		s = r.byDom[dom]
	}
	r.mu.RUnlock()
	return s.NewSigner(returnPath, header)
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
