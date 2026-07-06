// Host-side account_scan prep: enumerate account blobs and spawn the plugin.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BeaverMail/beaver/internal/pluginhost"
	"github.com/BeaverMail/beaver/internal/runtime"
	"github.com/BeaverMail/beaver/plugin"
)

// RunAccountScan builds a standard manifest and runs a account_scan profile plugin job.
func RunAccountScan(ctx context.Context, opts RunOptions, accountEmail string, params map[string]string) error {
	stack, err := runtime.OpenMailStack(ctx, opts.ConfigPath)
	if err != nil {
		return err
	}
	defer stack.Close()

	accountID, err := stack.AccountID(ctx, accountEmail)
	if err != nil {
		return fmt.Errorf("pluginhost: account: %w", err)
	}
	targets, cleanup, err := pluginhost.ListAccountScanTargets(ctx, stack, accountID)
	if err != nil {
		return err
	}
	defer cleanup()

	manifest := plugin.AccountScanManifest{AccountEmail: accountEmail}
	for _, t := range targets {
		manifest.Messages = append(manifest.Messages, plugin.AccountScanMessage{
			BodyPath: t.BodyPath,
			Mailbox:  t.Mailbox,
			UID:      t.UID,
		})
	}

	if err := os.MkdirAll(filepath.Join(stack.Cfg.DataDir, "tmp"), 0o755); err != nil {
		return err
	}
	manifestPath := filepath.Join(stack.Cfg.DataDir, "tmp", "account-scan-manifest.json")
	b, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(manifestPath, b, 0o600); err != nil {
		return err
	}
	defer os.Remove(manifestPath)

	params["manifest"] = manifestPath
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req := opts.Request
	req.Params = raw
	opts.Request = req
	return RunAdmin(ctx, opts)
}
