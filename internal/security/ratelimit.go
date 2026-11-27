// In-memory per-IP auth rate limiting (fail2ban phase 1).
package security

import (
	"strings"
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

// RateLimitGate blocks auth after MaxAttempts failures from one IP (an IPv6 /64) within Window.
type RateLimitGate struct {
	cfg     RateLimitConfig
	mu      sync.Mutex
	byIP    map[string]*rateBucket
	pruneAt int // map size that triggers dropping expired buckets
	nowFunc func() time.Time
}

// rateBucket counts the failures of one address, also per user name: a success forgives only the
// failures under its own name, so signing in to one account never resets guesses at another.
type rateBucket struct {
	count  int
	start  time.Time
	byName map[string]int
}

// minPrune is the map size below which expired buckets are left until reused.
const minPrune = 1024

// rateName is the per-name key: the case and spaces the directory ignores too, so two spellings
// share a key only when they name one account.
func rateName(user string) string { return strings.ToLower(strings.TrimSpace(user)) }

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
	return g.countLocked(ipNetworkKey(ip)) < g.cfg.MaxAttempts
}

// RecordAuthFailure increments the failure counter for ip and user.
func (g *RateLimitGate) RecordAuthFailure(ip, user string) {
	if ip == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now, key := g.nowFunc(), ipNetworkKey(ip)
	b := g.byIP[key]
	if b == nil || now.Sub(b.start) >= g.cfg.Window {
		g.pruneLocked(now)
		b = &rateBucket{start: now, byName: map[string]int{}}
		g.byIP[key] = b
	}
	b.count++
	b.byName[rateName(user)]++
}

// RecordAuthSuccess forgives the failures from ip under user's name only.
func (g *RateLimitGate) RecordAuthSuccess(ip, user string) {
	if ip == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	key, name := ipNetworkKey(ip), rateName(user)
	b := g.byIP[key]
	if b == nil {
		return
	}
	b.count -= b.byName[name]
	delete(b.byName, name)
	if b.count <= 0 {
		delete(g.byIP, key)
	}
}

// pruneLocked drops expired buckets once the map has doubled since the last sweep, so addresses
// that failed once and never came back do not accumulate.
func (g *RateLimitGate) pruneLocked(now time.Time) {
	if len(g.byIP) < max(g.pruneAt, minPrune) {
		return
	}
	for k, b := range g.byIP {
		if now.Sub(b.start) >= g.cfg.Window {
			delete(g.byIP, k)
		}
	}
	g.pruneAt = 2 * len(g.byIP)
}

func (g *RateLimitGate) countLocked(ip string) int {
	now := g.nowFunc()
	b := g.byIP[ip]
	if b == nil || now.Sub(b.start) >= g.cfg.Window {
		return 0
	}
	return b.count
}
