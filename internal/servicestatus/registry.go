// Runtime service/listener status for admin ops.
package servicestatus

import (
	"sort"
	"sync"
)

// Listener / component states.
const (
	StateUp       = "up"
	StateDown     = "down"
	StateDisabled = "disabled"
	StateError    = "error"
)

// Entry describes one protocol listener or background component.
type Entry struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Listen string `json:"listen,omitempty"`
	State  string `json:"state"`
	Error  string `json:"error,omitempty"`
}

// Registry holds process-wide service status (safe for concurrent use).
type Registry struct {
	mu   sync.RWMutex
	byID map[string]Entry
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{byID: make(map[string]Entry)}
}

// Set upserts an entry by ID.
func (r *Registry) Set(e Entry) {
	if r == nil || e.ID == "" {
		return
	}
	r.mu.Lock()
	r.byID[e.ID] = e
	r.mu.Unlock()
}

// List returns entries sorted by ID.
func (r *Registry) List() []Entry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]Entry, 0, len(r.byID))
	for _, e := range r.byID {
		out = append(out, e)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
