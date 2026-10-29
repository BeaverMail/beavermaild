// RunAdmin spawns an admin CLI plugin without mail ingest (filter reload, status).
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/BeaverMail/beavermaild/internal/config"
	"github.com/BeaverMail/beavermaild/internal/pluginhost"
	"github.com/BeaverMail/beavermaild/plugin"
)

// RunAdmin executes an admin-kind plugin subprocess (no account or ingest).
func RunAdmin(ctx context.Context, opts RunOptions) error {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("pluginhost: config: %w", err)
	}
	pluginsDir := filepath.Join(cfg.DataDir, "plugins")
	reg, err := pluginhost.LoadRegistry(pluginsDir)
	if err != nil {
		return err
	}
	exe, err := reg.ResolveExe(opts.Entry)
	if err != nil {
		return err
	}

	req := opts.Request
	req.APIVersion = plugin.APIVersion
	req.BeaverVersion = opts.BeaverVersion
	if req.Op == "" {
		req.Op = opts.Entry.Op()
	}
	reqLine, err := json.Marshal(req)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, exe)
	cmd.Env = append(os.Environ(), plugin.EnvDataDir+"="+cfg.DataDir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("pluginhost: start plugin: %w", err)
	}
	if _, err := stdin.Write(append(reqLine, '\n')); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	_ = stdin.Close()

	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			_ = cmd.Wait()
			return err
		}
		ev, err := plugin.ParseCliEvent(sc.Bytes())
		if err != nil {
			_ = cmd.Wait()
			return fmt.Errorf("pluginhost: parse event: %w", err)
		}
		switch ev.Op {
		case plugin.CliOpReport:
			if ev.Message != "" {
				fmt.Fprintln(os.Stdout, ev.Message)
			}
		case plugin.CliOpDone:
			if ev.Message != "" {
				fmt.Fprintln(os.Stderr, ev.Message)
			}
			if err := cmd.Wait(); err != nil {
				return fmt.Errorf("pluginhost: plugin exit: %w", err)
			}
			return nil
		case plugin.CliOpError:
			_ = cmd.Wait()
			if ev.Message != "" {
				return fmt.Errorf("%s", ev.Message)
			}
			return fmt.Errorf("plugin failed")
		}
	}
	if err := sc.Err(); err != nil {
		_ = cmd.Wait()
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("pluginhost: plugin exit: %w", err)
	}
	return fmt.Errorf("pluginhost: plugin stdout closed without done event")
}
