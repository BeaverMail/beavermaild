// Chain runs SMTP filter requests through all ready daemon plugins.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/BeaverMail/beaver/internal/smtp"
)

type filterPeer interface {
	ready() bool
	filter(ctx context.Context, req smtp.FilterRequest) (string, error)
}

// Chain implements smtp.MessageFilter across spawned SMTP daemon plugins.
type Chain struct {
	log      *slog.Logger
	plugins  []filterPeer
	timeout  time.Duration
	failOpen bool
}

// NewChain builds a filter chain from active plugin sessions.
func NewChain(log *slog.Logger, plugins []*pluginSession, timeout time.Duration, failOpen bool) *Chain {
	peers := make([]filterPeer, len(plugins))
	for i, p := range plugins {
		peers[i] = p
	}
	return &Chain{log: log, plugins: peers, timeout: timeout, failOpen: failOpen}
}

// Filter asks each ready plugin in order; first non-accept action wins.
func (c *Chain) Filter(ctx context.Context, req smtp.FilterRequest) (string, error) {
	if len(c.plugins) == 0 {
		return smtp.FilterActionAccept, nil
	}
	if req.TimeoutMs <= 0 {
		req.TimeoutMs = int(c.timeout / time.Millisecond)
	}
	for _, p := range c.plugins {
		if !p.ready() {
			continue
		}
		timeout := time.Duration(req.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = c.timeout
		}
		filterCtx, cancel := context.WithTimeout(ctx, timeout)
		action, err := p.filter(filterCtx, req)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errFilterTimeout) {
				c.log.Warn("plugin_timeout",
					"id", req.ID,
					"phase", req.Phase,
					"timeout_ms", req.TimeoutMs,
				)
				if c.failOpen {
					continue
				}
				return smtp.FilterActionTempfail, nil
			}
			c.log.Warn("plugin_filter_error", slog.Any("err", err))
			if c.failOpen {
				continue
			}
			return smtp.FilterActionTempfail, nil
		}
		if action != smtp.FilterActionAccept {
			return action, nil
		}
	}
	return smtp.FilterActionAccept, nil
}
