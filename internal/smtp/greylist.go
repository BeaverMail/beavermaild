// Persistent SMTP greylisting at the RCPT stage.
package smtp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/BeaverMail/beaver/internal/storage"
)

const greylistKeyPrefix = "greylist/"

// GreylistConfig controls retry timing for unauthenticated inbound mail.
type GreylistConfig struct {
	Enabled  bool
	MinDelay time.Duration
	MaxAge   time.Duration
}

// Greylist persists accepted retry windows by sender/recipient/client triplet.
type Greylist struct {
	store storage.Store
	cfg   GreylistConfig
	now   func() time.Time
	mu    sync.Mutex
}

// NewGreylist constructs a disabled-by-default persistent greylist.
func NewGreylist(store storage.Store, cfg GreylistConfig) *Greylist {
	if !cfg.Enabled || store == nil {
		return nil
	}
	if cfg.MinDelay <= 0 {
		cfg.MinDelay = 5 * time.Minute
	}
	if cfg.MaxAge <= cfg.MinDelay {
		cfg.MaxAge = 36 * time.Hour
	}
	return &Greylist{store: store, cfg: cfg, now: time.Now}
}

// Allow reports whether a triplet has aged through the retry delay.
func (g *Greylist) Allow(ctx context.Context, clientIP, mailFrom, rcptTo string) (bool, error) {
	if g == nil {
		return true, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	key, suffix := greylistKeys(clientIP, mailFrom, rcptTo)
	wire, err := g.store.Get(ctx, key)
	now := g.now()
	if errors.Is(err, storage.ErrNotFound) {
		return false, g.save(ctx, suffix, now)
	}
	if err != nil {
		return false, err
	}
	if len(wire) != 8 {
		return false, g.save(ctx, suffix, now)
	}
	first := time.Unix(int64(binary.BigEndian.Uint64(wire)), 0)
	age := now.Sub(first)
	if age < 0 || age > g.cfg.MaxAge {
		return false, g.save(ctx, suffix, now)
	}
	return age >= g.cfg.MinDelay, nil
}

// save stores the first-seen timestamp for a triplet.
func (g *Greylist) save(ctx context.Context, suffix []byte, at time.Time) error {
	var wire [8]byte
	binary.BigEndian.PutUint64(wire[:], uint64(at.Unix()))
	batch := storage.NewBatch().WithAccount(0)
	if err := batch.Set(storage.SubspaceLookup, suffix, wire[:]); err != nil {
		return err
	}
	return g.store.Commit(ctx, batch)
}

// greylistKeys returns full and batch-suffix keys for normalized triplet state.
func greylistKeys(clientIP, mailFrom, rcptTo string) ([]byte, []byte) {
	clientIP = normalizeGreylistIP(clientIP)
	mailFrom = normalizeEnvelopeAddress(mailFrom)
	rcptTo = normalizeEnvelopeAddress(rcptTo)
	sum := sha256.Sum256([]byte(clientIP + "\x00" + mailFrom + "\x00" + rcptTo))
	tail := append([]byte(greylistKeyPrefix), sum[:]...)
	suffix := storage.DocumentSuffix(0, 0, tail)
	key := storage.AppendKey(nil, storage.SubspaceLookup, 0, 0, 0, tail)
	return key, suffix
}

func normalizeGreylistIP(value string) string {
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		value = host
	}
	if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
		return ip.String()
	}
	return strings.ToLower(strings.TrimSpace(value))
}
