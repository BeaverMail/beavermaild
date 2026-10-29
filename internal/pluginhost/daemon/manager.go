// Daemon plugin manager: spawn SMTP filter plugins for beaver serve.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BeaverMail/beavermaild/internal/pluginhost"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/plugin"
)

// Manager loads daemon-capable plugins and manages their lifecycle.
type Manager struct {
	log            *slog.Logger
	socketDir      string
	dataDir        string
	timeout        time.Duration
	failOpen       bool
	restartBackoff time.Duration
	registry       *pluginhost.Registry
	sessions       []*pluginSession
	chain          smtp.MessageFilter

	ctx      context.Context
	cancel   context.CancelFunc
	stopping atomic.Bool
	watchWg  sync.WaitGroup
}

// Config holds daemon manager runtime settings.
type Config struct {
	SocketDir      string
	DataDir        string
	Timeout        time.Duration
	FailOpen       bool
	RestartBackoff time.Duration
}

// NewManager creates a daemon manager for pluginsDir.
func NewManager(log *slog.Logger, cfg Config) *Manager {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.RestartBackoff <= 0 {
		cfg.RestartBackoff = time.Second
	}
	return &Manager{
		log:            log,
		socketDir:      cfg.SocketDir,
		dataDir:        cfg.DataDir,
		timeout:        cfg.Timeout,
		failOpen:       cfg.FailOpen,
		restartBackoff: cfg.RestartBackoff,
		chain:          smtp.NopFilter{},
	}
}

// LoadFromRegistry records daemon entries from the registry (no spawn yet).
func (m *Manager) LoadFromRegistry(reg *pluginhost.Registry) error {
	m.registry = reg
	for _, e := range reg.DaemonEntries() {
		if !e.HasCapability(plugin.CapSMTP) {
			continue
		}
		if _, err := reg.ResolveExe(e); err != nil {
			return fmt.Errorf("daemon: plugin %q: %w", e.Name, err)
		}
	}
	return nil
}

// Start spawns SMTP daemon plugins and waits for ready handshake.
func (m *Manager) Start(ctx context.Context) error {
	if m.registry == nil {
		m.chain = smtp.NopFilter{}
		return nil
	}
	m.ctx, m.cancel = context.WithCancel(ctx)
	if err := mkdirAll(m.socketDir); err != nil {
		return err
	}
	var sessions []*pluginSession
	for _, e := range m.registry.DaemonEntries() {
		if !e.HasCapability(plugin.CapSMTP) {
			continue
		}
		exe, err := m.registry.ResolveExe(e)
		if err != nil {
			for _, s := range sessions {
				s.stop()
			}
			return err
		}
		socketPath := filepath.Join(m.socketDir, e.Name+".sock")
		sess, err := spawnPluginSession(m.ctx, e.Name, exe, socketPath, m.dataDir)
		if err != nil {
			for _, s := range sessions {
				s.stop()
			}
			return err
		}
		m.log.Info("smtp plugin ready", "plugin", e.Name, "socket", socketPath)
		sessions = append(sessions, sess)
		m.watchWg.Add(1)
		go m.watchSession(sess)
	}
	m.sessions = sessions
	m.chain = NewChain(m.log, sessions, m.timeout, m.failOpen)
	return nil
}

// watchSession waits for plugin exit and respawns until Manager.Stop.
func (m *Manager) watchSession(p *pluginSession) {
	defer m.watchWg.Done()
	for {
		err := p.waitProcess()
		if m.stopping.Load() || m.ctx.Err() != nil {
			return
		}
		m.log.Warn("plugin_exit", "plugin", p.name, slog.Any("err", err))

		for {
			if m.stopping.Load() || m.ctx.Err() != nil {
				return
			}
			select {
			case <-m.ctx.Done():
				return
			case <-time.After(m.restartBackoff):
			}
			if err := p.reconnect(m.ctx); err != nil {
				m.log.Warn("plugin_restart_failed",
					"plugin", p.name,
					"backoff_ms", m.restartBackoff.Milliseconds(),
					slog.Any("err", err),
				)
				continue
			}
			m.log.Info("smtp plugin ready", "plugin", p.name, "socket", p.socket)
			break
		}
	}
}

// Filter returns the SMTP message filter chain.
func (m *Manager) Filter() smtp.MessageFilter {
	if m.chain == nil {
		return smtp.NopFilter{}
	}
	return m.chain
}

// Stop terminates spawned daemon plugins.
func (m *Manager) Stop() error {
	m.stopping.Store(true)
	if m.cancel != nil {
		m.cancel()
	}
	for _, s := range m.sessions {
		s.stop()
	}
	m.watchWg.Wait()
	m.sessions = nil
	m.chain = smtp.NopFilter{}
	return nil
}

func mkdirAll(dir string) error {
	return osMkdirAll(dir, 0o755)
}

// osMkdirAll is a test seam.
var osMkdirAll = func(path string, perm os.FileMode) error {
	return mkdirAllImpl(path, perm)
}

func mkdirAllImpl(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}
