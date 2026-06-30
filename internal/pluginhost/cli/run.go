// CLI plugin runner: spawn subprocess, JSONL protocol on stdio.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/BeaverMail/beaver/internal/pluginhost"
	"github.com/BeaverMail/beaver/internal/runtime"
	"github.com/BeaverMail/beaver/plugin"
)

// RunOptions configures a CLI plugin subprocess invocation.
type RunOptions struct {
	ConfigPath    string
	BeaverVersion string
	Entry         pluginhost.Entry
	Request       plugin.CliRequest
	ClearRecent   bool
}

// Run opens the mail stack, spawns the plugin, ingests JSONL from stdout.
func Run(ctx context.Context, opts RunOptions) (plugin.JobResult, error) {
	stack, err := runtime.OpenMailStack(ctx, opts.ConfigPath)
	if err != nil {
		return plugin.JobResult{}, err
	}
	defer stack.Close()

	mail := pluginhost.NewHostMail(stack)
	accountID, err := mail.AccountID(ctx, opts.Request.AccountEmail)
	if err != nil {
		return plugin.JobResult{}, fmt.Errorf("pluginhost: account: %w", err)
	}
	if err := mail.EnsureMailboxes(ctx, accountID); err != nil {
		return plugin.JobResult{}, err
	}
	known, err := mail.AccountHashIndex(ctx, accountID)
	if err != nil {
		return plugin.JobResult{}, err
	}

	pluginsDir := filepath.Join(stack.Cfg.DataDir, "plugins")
	reg, err := pluginhost.LoadRegistry(pluginsDir)
	if err != nil {
		return plugin.JobResult{}, err
	}
	exe, err := reg.ResolveExe(opts.Entry)
	if err != nil {
		return plugin.JobResult{}, err
	}

	req := opts.Request
	req.APIVersion = plugin.APIVersion
	req.BeaverVersion = opts.BeaverVersion
	req.Op = opts.Entry.Op()
	reqLine, err := json.Marshal(req)
	if err != nil {
		return plugin.JobResult{}, err
	}

	cmd := exec.CommandContext(ctx, exe)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return plugin.JobResult{}, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return plugin.JobResult{}, err
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return plugin.JobResult{}, fmt.Errorf("pluginhost: start plugin: %w", err)
	}

	if _, err := stdin.Write(append(reqLine, '\n')); err != nil {
		_ = cmd.Process.Kill()
		return plugin.JobResult{}, err
	}
	_ = stdin.Close()

	ing := NewIngester(mail, accountID, req.DryRun, known)
	if err := readEvents(ctx, stdout, ing); err != nil {
		_ = cmd.Wait()
		return plugin.JobResult{}, err
	}
	if err := cmd.Wait(); err != nil {
		return plugin.JobResult{}, fmt.Errorf("pluginhost: plugin exit: %w", err)
	}
	if opts.ClearRecent && !req.DryRun {
		if err := clearRecentOnMailboxes(ctx, ing, mail, accountID); err != nil {
			return plugin.JobResult{}, err
		}
	}
	return ing.Result(), nil
}

func clearRecentOnMailboxes(ctx context.Context, ing *Ingester, mail *pluginhost.HostMail, accountID uint32) error {
	for _, imapName := range ing.TouchedMailboxes() {
		mboxID, err := mail.ResolveMailbox(ctx, accountID, imapName)
		if err != nil {
			return err
		}
		if err := mail.ClearRecent(ctx, accountID, mboxID); err != nil {
			return err
		}
	}
	return nil
}

func readEvents(ctx context.Context, r io.Reader, ing *Ingester) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		ev, err := plugin.ParseCliEvent(sc.Bytes())
		if err != nil {
			return fmt.Errorf("pluginhost: parse event: %w", err)
		}
		done, err := ing.Apply(ctx, ev)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return fmt.Errorf("pluginhost: plugin stdout closed without done event")
}
