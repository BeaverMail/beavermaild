// pluginSession holds one connected SMTP daemon plugin subprocess.
package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/plugin"
)

var errFilterTimeout = errors.New("daemon: filter timeout")

type pluginSession struct {
	name    string
	socket  string
	exe     string
	dataDir string
	cmd     *exec.Cmd
	conn    net.Conn
	mu      sync.Mutex
	isReady bool
}

func (p *pluginSession) ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.isReady && p.conn != nil
}

func (p *pluginSession) filter(ctx context.Context, req smtp.FilterRequest) (smtp.FilterOutcome, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil || !p.isReady {
		return smtp.FilterOutcome{Action: smtp.FilterActionAccept}, nil
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	reqLine, err := json.Marshal(encodeFilterRequest(req))
	if err != nil {
		return smtp.FilterOutcome{}, err
	}
	done := make(chan error, 1)
	var resp FilterResponse
	go func() {
		if _, err := p.conn.Write(append(reqLine, '\n')); err != nil {
			done <- err
			return
		}
		sc := bufio.NewScanner(p.conn)
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				done <- err
				return
			}
			done <- io.EOF
			return
		}
		if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
			done <- err
			return
		}
		done <- nil
	}()
	select {
	case <-ctx.Done():
		return smtp.FilterOutcome{}, errFilterTimeout
	case err := <-done:
		if err != nil {
			p.markDeadLocked()
			return smtp.FilterOutcome{}, err
		}
		if resp.ID != "" && resp.ID != req.ID {
			return smtp.FilterOutcome{}, fmt.Errorf("daemon: response id mismatch")
		}
		if resp.Action == "" {
			return smtp.FilterOutcome{}, fmt.Errorf("daemon: empty action")
		}
		return decodeFilterOutcome(resp), nil
	}
}

func (p *pluginSession) markDeadLocked() {
	p.isReady = false
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}
}

func (p *pluginSession) waitProcess() error {
	p.mu.Lock()
	cmd := p.cmd
	p.mu.Unlock()
	if cmd == nil {
		return fmt.Errorf("daemon: %q no process", p.name)
	}
	return cmd.Wait()
}

func (p *pluginSession) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.markDeadLocked()
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
	_ = os.Remove(p.socket)
}

// connectSession spawns the plugin and completes the ready handshake. Caller must hold p.mu.
func (p *pluginSession) connectSession(ctx context.Context) error {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
		p.cmd = nil
	}
	p.markDeadLocked()

	_ = os.Remove(p.socket)
	if err := os.MkdirAll(filepath.Dir(p.socket), 0o755); err != nil {
		return err
	}
	ln, err := net.Listen("unix", p.socket)
	if err != nil {
		return err
	}
	defer ln.Close()

	cmd := exec.CommandContext(ctx, p.exe)
	env := []string{
		plugin.EnvPluginMode + "=" + plugin.PluginModeDaemon,
		"BEAVER_SMTP_SOCKET=" + p.socket,
	}
	if p.dataDir != "" {
		env = append(env, plugin.EnvDataDir+"="+p.dataDir)
	}
	cmd.Env = append(os.Environ(), env...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("daemon: start %q: %w", p.name, err)
	}

	acceptCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var conn net.Conn
	acceptDone := make(chan error, 1)
	go func() {
		conn, err = ln.Accept()
		acceptDone <- err
	}()
	select {
	case <-acceptCtx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("daemon: %q ready timeout", p.name)
	case err := <-acceptDone:
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return err
		}
	}

	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		_ = conn.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("daemon: %q no ready line", p.name)
	}
	var ready ReadyLine
	if err := json.Unmarshal(sc.Bytes(), &ready); err != nil {
		_ = conn.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("daemon: %q parse ready: %w", p.name, err)
	}
	if ready.Status != "ready" {
		_ = conn.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("daemon: %q status %q", p.name, ready.Status)
	}

	p.cmd = cmd
	p.conn = conn
	p.isReady = true
	return nil
}

func (p *pluginSession) reconnect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connectSession(ctx)
}

func spawnPluginSession(ctx context.Context, name, exe, socketPath, dataDir string) (*pluginSession, error) {
	p := &pluginSession{
		name:    name,
		socket:  socketPath,
		exe:     exe,
		dataDir: dataDir,
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.connectSession(ctx); err != nil {
		return nil, err
	}
	return p, nil
}
