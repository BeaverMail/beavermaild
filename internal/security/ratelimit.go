// In-memory per-IP auth rate limiting (fail2ban phase 1).
package security

import (
	"sync"
	"time"
)

// RateLimitConfig configures auth attempt counters before temporary lockout.
type RateLimitConfig struct {
	MaxAttempts int
	Window      time.Duration
}

// DefaultRateLimitConfig is used when config omits auth.rate_limit fields.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{MaxAttempts: 10, Window: 15 * time.Minute}
}

// RateLimitGate blocks auth after MaxAttempts failures from one IP within Window.
type RateLimitGate struct {
	cfg     RateLimitConfig
	mu      sync.Mutex
	byIP    map[string]*rateBucket
	nowFunc func() time.Time
}

type rateBucket struct {
	count int
	start time.Time
}

// NewRateLimitGate returns an in-memory auth gate with cfg (zero fields get defaults).
func NewRateLimitGate(cfg RateLimitConfig) *RateLimitGate {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultRateLimitConfig().MaxAttempts
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultRateLimitConfig().Window
	}
	return &RateLimitGate{
		cfg:     cfg,
		byIP:    make(map[string]*rateBucket),
		nowFunc: time.Now,
	}
}

// SetClockForTest overrides the clock (tests only).
func (g *RateLimitGate) SetClockForTest(now func() time.Time) {
	if now != nil {
		g.nowFunc = now
	}
}

// AllowAuth reports whether another auth attempt from ip is allowed.
func (g *RateLimitGate) AllowAuth(ip, _ string) bool {
	if ip == "" {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.countLocked(ip) < g.cfg.MaxAttempts
}

// RecordAuthFailure increments the failure counter for ip.
func (g *RateLimitGate) RecordAuthFailure(ip, _ string) {
	if ip == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.nowFunc()
	b := g.byIP[ip]
	if b == nil || now.Sub(b.start) >= g.cfg.Window {
		g.byIP[ip] = &rateBucket{count: 1, start: now}
		return
	}
	b.count++
}

// RecordAuthSuccess clears the failure counter for ip.
func (g *RateLimitGate) RecordAuthSuccess(ip, _ string) {
	if ip == "" {
		return
	}
	g.mu.Lock()
	delete(g.byIP, ip)
	g.mu.Unlock()
}

func (g *RateLimitGate) countLocked(ip string) int {
	now := g.nowFunc()
	b := g.byIP[ip]
	if b == nil || now.Sub(b.start) >= g.cfg.Window {
		return 0
	}
	return b.count
}
