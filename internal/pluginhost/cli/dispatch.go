// Generic CLI dispatch: match argv prefix to registry command, run plugin.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BeaverMail/beaver/internal/cli"
	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/pluginhost"
	"github.com/BeaverMail/beaver/plugin"
)

// DispatchOptions configures registry-based CLI plugin dispatch.
type DispatchOptions struct {
	Args          []string
	BeaverVersion string
}

// TryDispatch matches args to a CLI plugin command in the registry and runs it.
// Returns (exitCode, true) when a plugin handled the invocation; (_, false) if no match.
func TryDispatch(ctx context.Context, opts DispatchOptions) (int, bool) {
	cmd, flagArgs := splitCommandAndFlags(opts.Args)
	if len(cmd) == 0 {
		return 0, false
	}

	defaultConfig := config.DefaultConfigPath()
	reg, err := loadRegistry(defaultConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugins: %v\n", err)
		return cli.ExitError, true
	}

	if isHelpRequest(flagArgs) {
		return dispatchPluginHelp(reg, cmd)
	}

	if entry, ok := reg.Find(cmd); ok {
		return runPluginCommand(ctx, opts, entry, flagArgs)
	}

	matches := reg.FindCLIByPrefix(cmd)
	if len(matches) == 0 {
		return 0, false
	}
	if len(matches) == 1 {
		printPluginUsage(matches[0])
		if len(matches[0].Command) > len(cmd) {
			fmt.Fprintf(os.Stderr, "complete command: beaver %s\n", strings.Join(matches[0].Command, " "))
		}
		return cli.ExitUsage, true
	}
	printPluginAmbiguousUsage(matches)
	return cli.ExitUsage, true
}

func dispatchPluginHelp(reg *pluginhost.Registry, cmd []string) (int, bool) {
	if entry, ok := reg.Find(cmd); ok {
		printPluginUsage(entry)
		return cli.ExitOK, true
	}
	matches := reg.FindCLIByPrefix(cmd)
	if len(matches) == 0 {
		return 0, false
	}
	if len(matches) == 1 {
		printPluginUsage(matches[0])
		return cli.ExitOK, true
	}
	printPluginAmbiguousUsage(matches)
	return cli.ExitUsage, true
}

func runPluginCommand(ctx context.Context, opts DispatchOptions, entry pluginhost.Entry, flagArgs []string) (int, bool) {
	cmd := entry.Command
	defaultConfig := config.DefaultConfigPath()
	parsed, err := parsePluginFlags(flagArgs, defaultConfig, entry.CliFlags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin %s: %v\n", strings.Join(cmd, " "), err)
		if hint := pluginFlagHint(entry, err); hint != "" {
			fmt.Fprintln(os.Stderr, hint)
		}
		printPluginUsage(entry)
		return cli.ExitUsage, true
	}

	if parsed.configPath != defaultConfig {
		entry, err = loadCLIEntry(parsed.configPath, cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "plugin %s: %v\n", strings.Join(cmd, " "), err)
			return cli.ExitError, true
		}
	}

	params, err := json.Marshal(parsed.params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin %s: %v\n", strings.Join(cmd, " "), err)
		return cli.ExitError, true
	}

	res, err := Run(ctx, RunOptions{
		ConfigPath:    parsed.configPath,
		BeaverVersion: opts.BeaverVersion,
		Entry:         entry,
		ClearRecent:   parsed.clearRecent,
		Verbose:       parsed.verbose,
		Request: plugin.CliRequest{
			AccountEmail: parsed.account,
			DryRun:       parsed.dryRun,
			Params:       params,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin %s: %v\n", strings.Join(cmd, " "), err)
		return cli.ExitError, true
	}
	fmt.Fprintln(os.Stderr, formatJobTotalsLine(res))
	printMailboxTotals(res.ByMailbox)
	return cli.ExitOK, true
}

// formatJobTotalsLine renders account-level ingest totals with optional skip breakdown.
func formatJobTotalsLine(res plugin.JobResult) string {
	line := fmt.Sprintf("imported=%d skipped=%d errors=%d", res.Imported, res.Skipped, res.Errors)
	if res.Skipped > 0 {
		line += formatSkipBreakdown(res.SkipBreakdown)
	}
	return line
}

// formatSkipBreakdown renders non-zero skip reason counts.
func formatSkipBreakdown(b plugin.SkipBreakdown) string {
	var parts []string
	if b.DuplicateInAccount > 0 {
		parts = append(parts, fmt.Sprintf("duplicate_in_account=%d", b.DuplicateInAccount))
	}
	if b.DuplicateInBatch > 0 {
		parts = append(parts, fmt.Sprintf("duplicate_in_batch=%d", b.DuplicateInBatch))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, " ") + ")"
}

// formatMailboxTotalsLine renders per-mailbox ingest totals with optional skip breakdown.
func formatMailboxTotalsLine(name string, c plugin.MailboxCounts) string {
	line := fmt.Sprintf("  %s: imported=%d skipped=%d errors=%d", name, c.Imported, c.Skipped, c.Errors)
	if c.Skipped > 0 {
		line += formatSkipBreakdown(c.SkipBreakdown)
	}
	return line
}

func printMailboxTotals(byMailbox map[string]plugin.MailboxCounts) {
	if len(byMailbox) == 0 {
		return
	}
	names := make([]string, 0, len(byMailbox))
	for name := range byMailbox {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintln(os.Stderr, formatMailboxTotalsLine(name, byMailbox[name]))
	}
}

func registryHasCommand(configPath string, cmd []string) bool {
	reg, err := loadRegistry(configPath)
	if err != nil {
		return false
	}
	_, ok := reg.Find(cmd)
	return ok
}

func loadCLIEntry(configPath string, cmd []string) (pluginhost.Entry, error) {
	reg, err := loadRegistry(configPath)
	if err != nil {
		return pluginhost.Entry{}, err
	}
	entry, ok := reg.Find(cmd)
	if !ok {
		return pluginhost.Entry{}, fmt.Errorf("plugin not found for command %q", strings.Join(cmd, " "))
	}
	return entry, nil
}

func loadRegistry(configPath string) (*pluginhost.Registry, error) {
	return pluginhost.LoadRegistry(pluginhost.PluginsDirFromConfigPath(configPath))
}

type pluginFlags struct {
	configPath  string
	account     string
	dryRun      bool
	clearRecent bool
	verbose     bool
	params      map[string]string
}

func parsePluginFlags(args []string, defaultConfig string, cliFlags []plugin.CliFlag) (pluginFlags, error) {
	out := pluginFlags{
		configPath:  defaultConfig,
		clearRecent: true,
		params:      make(map[string]string),
	}
	fs := flag.NewFlagSet("plugin", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&out.configPath, "c", defaultConfig, "config file path")
	fs.StringVar(&out.account, "account", "", "destination account email (mail ingest plugins)")
	fs.BoolVar(&out.dryRun, "dry-run", false, "simulate without writing messages")
	fs.BoolVar(&out.clearRecent, "clear-recent", true, "clear \\Recent after ingest")
	fs.BoolVar(&out.verbose, "verbose", false, "extra stderr detail from plugin and host")
	for _, f := range cliFlags {
		if f.Key == "" || f.Flag == "" {
			return pluginFlags{}, fmt.Errorf("invalid cli_flags entry (need key and flag)")
		}
		key := f.Key
		desc := f.Description
		if desc == "" {
			desc = "plugin parameter " + key
		}
		fs.Func(f.Flag, desc, func(s string) error {
			out.params[key] = s
			return nil
		})
	}
	fs.Func("param", "plugin argument key=value (repeatable)", func(s string) error {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			return fmt.Errorf("invalid -param %q (want key=value)", s)
		}
		out.params[k] = v
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return pluginFlags{}, err
	}
	if out.account == "" {
		return pluginFlags{}, fmt.Errorf("-account is required")
	}
	for _, f := range cliFlags {
		if f.Required && out.params[f.Key] == "" {
			return pluginFlags{}, fmt.Errorf("-%s is required", f.Flag)
		}
	}
	return out, nil
}

// pluginFlagHint suggests descriptor cli_flags when a dedicated flag is rejected.
func pluginFlagHint(entry pluginhost.Entry, err error) string {
	if len(entry.CliFlags) > 0 || err == nil {
		return ""
	}
	if !strings.Contains(err.Error(), "not defined") {
		return ""
	}
	return "hint: dedicated plugin flags need cli_flags in plugin descriptor (EmitDescriptor); without them use -param key=value (check: beaver plugins list)"
}

func splitCommandAndFlags(args []string) (cmd []string, flags []string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			return args[:i], args[i:]
		}
	}
	return args, nil
}

func isHelpRequest(args []string) bool {
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			return true
		}
	}
	return false
}

func printPluginUsage(entry pluginhost.Entry) {
	fmt.Fprintf(os.Stderr, "usage: beaver %s [-c path] -account email [-dry-run] [-clear-recent] [-verbose]",
		strings.Join(entry.Command, " "))
	for _, f := range entry.CliFlags {
		req := ""
		if f.Required {
			req = " (required)"
		}
		fmt.Fprintf(os.Stderr, " [-%s path%s]", f.Flag, req)
	}
	fmt.Fprintln(os.Stderr, " [-param key=value ...]")
}

func printPluginAmbiguousUsage(entries []pluginhost.Entry) {
	fmt.Fprintln(os.Stderr, "ambiguous plugin command, choose one:")
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Op() < entries[j].Op()
	})
	for _, e := range entries {
		fmt.Fprintf(os.Stderr, "  beaver %s ...\n", strings.Join(e.Command, " "))
	}
}
