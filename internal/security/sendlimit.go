// In-memory per-principal submission message rate limiting.
package security

import (
	"strings"
	"sync"
	"time"
)

// SendGate limits accepted outbound messages per authenticated principal.
// Implementations must be safe for concurrent use.
type SendGate interface {
	AllowSend(principal string) bool
	RecordSend(principal string)
}

// NopSendGate disables submission message rate limiting.
type NopSendGate struct{}

func (NopSendGate) AllowSend(string) bool { return true }
func (NopSendGate) RecordSend(string)     {}

// SendLimitConfig configures accepted messages per principal before temporary refusal.
type SendLimitConfig struct {
	MaxMessages int
	Window      time.Duration
}

// DefaultSendLimitConfig is used when config omits smtp.submission_rate_limit fields.
func DefaultSendLimitConfig() SendLimitConfig {
	return SendLimitConfig{MaxMessages: 200, Window: time.Hour}
}

// SendLimitGate blocks further accepts after MaxMessages from one principal within Window.
type SendLimitGate struct {
	cfg     SendLimitConfig
	mu      sync.Mutex
	byKey   map[string]*rateBucket
	nowFunc func() time.Time
}

// NewSendLimitGate returns an in-memory send gate with cfg (zero fields get defaults).
func NewSendLimitGate(cfg SendLimitConfig) *SendLimitGate {
	if cfg.MaxMessages <= 0 {
		cfg.MaxMessages = DefaultSendLimitConfig().MaxMessages
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultSendLimitConfig().Window
	}
	return &SendLimitGate{
		cfg:     cfg,
		byKey:   make(map[string]*rateBucket),
		nowFunc: time.Now,
	}
}

// SetClockForTest overrides the clock (tests only).
func (g *SendLimitGate) SetClockForTest(now func() time.Time) {
	if now != nil {
		g.nowFunc = now
	}
}

// AllowSend reports whether another message from principal is allowed.
func (g *SendLimitGate) AllowSend(principal string) bool {
	key := normalizePrincipal(principal)
	if key == "" {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.countLocked(key) < g.cfg.MaxMessages
}

// RecordSend increments the accepted-message counter for principal.
func (g *SendLimitGate) RecordSend(principal string) {
	key := normalizePrincipal(principal)
	if key == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.nowFunc()
	b := g.byKey[key]
	if b == nil || now.Sub(b.start) >= g.cfg.Window {
		g.byKey[key] = &rateBucket{count: 1, start: now}
		return
	}
	b.count++
}

func (g *SendLimitGate) countLocked(key string) int {
	now := g.nowFunc()
	b := g.byKey[key]
	if b == nil || now.Sub(b.start) >= g.cfg.Window {
		return 0
	}
	return b.count
}

func normalizePrincipal(principal string) string {
	return strings.ToLower(strings.TrimSpace(principal))
}
