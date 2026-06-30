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

	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/plugin"
)

var errFilterTimeout = errors.New("daemon: filter timeout")

type pluginSession struct {
	name   string
	socket string
	exe    string
	cmd    *exec.Cmd
	conn   net.Conn
	mu      sync.Mutex
	isReady bool
}

func (p *pluginSession) ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.isReady && p.conn != nil
}

func (p *pluginSession) filter(ctx context.Context, req smtp.FilterRequest) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil || !p.isReady {
		return smtp.FilterActionAccept, nil
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	reqLine, err := json.Marshal(FilterRequest{
		ID:        req.ID,
		Phase:     req.Phase,
		From:      req.From,
		To:        req.To,
		ClientIP:  req.ClientIP,
		BodyPath:  req.BodyPath,
		TimeoutMs: req.TimeoutMs,
	})
	if err != nil {
		return "", err
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
		return "", errFilterTimeout
	case err := <-done:
		if err != nil {
			p.markDead()
			return "", err
		}
		if resp.ID != "" && resp.ID != req.ID {
			return "", fmt.Errorf("daemon: response id mismatch")
		}
		if resp.Action == "" {
			return "", fmt.Errorf("daemon: empty action")
		}
		return resp.Action, nil
	}
}

func (p *pluginSession) markDead() {
	p.isReady = false
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}
}

func (p *pluginSession) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.markDead()
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		_, _ = p.cmd.Process.Wait()
	}
	_ = os.Remove(p.socket)
}

func spawnPluginSession(ctx context.Context, name, exe, socketPath string) (*pluginSession, error) {
	_ = os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	cmd := exec.CommandContext(ctx, exe)
	cmd.Env = append(os.Environ(),
		plugin.EnvPluginMode+"="+plugin.PluginModeDaemon,
		"BEAVER_SMTP_SOCKET="+socketPath,
	)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("daemon: start %q: %w", name, err)
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
		return nil, fmt.Errorf("daemon: %q ready timeout", name)
	case err := <-acceptDone:
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, err
		}
	}

	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		_ = conn.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("daemon: %q no ready line", name)
	}
	var ready ReadyLine
	if err := json.Unmarshal(sc.Bytes(), &ready); err != nil {
		_ = conn.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("daemon: %q parse ready: %w", name, err)
	}
	if ready.Status != "ready" {
		_ = conn.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("daemon: %q status %q", name, ready.Status)
	}

	return &pluginSession{
		name:   name,
		socket: socketPath,
		exe:    exe,
		cmd:    cmd,
		conn:   conn,
		isReady: true,
	}, nil
}
