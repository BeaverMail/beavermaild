// Registry loads plugins by scanning binaries and probing metadata descriptors.
package pluginhost

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/BeaverMail/beaver/plugin"
)

// Entry describes one installed plugin discovered from a binary metadata probe.
type Entry struct {
	Name             string                 `json:"name"`
	Command          []string               `json:"command"`
	Exe              string                 `json:"exe"`
	CliFlags         []plugin.CliFlag       `json:"cli_flags,omitempty"`
	CliSubcommands   []plugin.CliSubcommand `json:"cli_subcommands,omitempty"`
	CliKind          string                 `json:"cli_kind,omitempty"`
	// Capabilities: cli = ephemeral CLI jobs; smtp/web = persistent daemon under beaver serve (see docs/plugins.md).
	Capabilities []string `json:"capabilities"`
}

// Registry resolves plugin executables for CLI and daemon capabilities.
type Registry struct {
	pluginsDir string
	entries    []Entry
}

// LoadRegistry scans pluginsDir for beaver-plugin-* binaries and probes each for a Descriptor.
func LoadRegistry(pluginsDir string) (*Registry, error) {
	r := &Registry{pluginsDir: pluginsDir}
	seenCmd := make(map[string]struct{})
	matches, err := filepath.Glob(filepath.Join(pluginsDir, "beaver-plugin-*"))
	if err != nil {
		return nil, err
	}
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		base := filepath.Base(path)
		entry, err := entryFromBinary(path, base)
		if err != nil {
			return nil, err
		}
		key := strings.Join(entry.Command, "/")
		if _, ok := seenCmd[key]; ok {
			continue
		}
		r.entries = append(r.entries, entry)
		seenCmd[key] = struct{}{}
	}
	return r, nil
}

// entryFromBinary builds a registry entry from defaults plus plugin metadata probe.
func entryFromBinary(exePath, base string) (Entry, error) {
	stem := strings.TrimPrefix(base, "beaver-plugin-")
	entry := Entry{
		Name:         stem,
		Command:      defaultCommandForExe(base),
		Exe:          base,
		Capabilities: []string{plugin.CapCLI},
	}
	desc, ok, err := probePluginDescriptor(exePath)
	if err != nil {
		return Entry{}, err
	}
	if ok {
		entry = mergeDescriptor(entry, desc)
		if err := validateCapabilities(entry.Capabilities); err != nil {
			return Entry{}, fmt.Errorf("pluginhost: plugin %q descriptor: %w", stem, err)
		}
	}
	return entry, nil
}

// mergeDescriptor overlays fields from a plugin metadata probe.
func mergeDescriptor(base Entry, desc plugin.Descriptor) Entry {
	if len(desc.Command) > 0 {
		base.Command = desc.Command
	}
	if len(desc.CliFlags) > 0 {
		base.CliFlags = desc.CliFlags
	}
	if len(desc.Capabilities) > 0 {
		base.Capabilities = normalizeCapabilities(desc.Capabilities)
	}
	if desc.CliKind != "" {
		base.CliKind = desc.CliKind
	}
	if len(desc.CliSubcommands) > 0 {
		base.CliSubcommands = desc.CliSubcommands
	}
	return base
}

func defaultCommandForExe(base string) []string {
	return []string{strings.TrimPrefix(base, "beaver-plugin-")}
}

func normalizeCapabilities(caps []string) []string {
	if len(caps) == 0 {
		return []string{plugin.CapCLI}
	}
	return caps
}

func validateCapabilities(caps []string) error {
	if len(caps) == 0 {
		return fmt.Errorf("capabilities required")
	}
	allowed := map[string]struct{}{
		plugin.CapCLI: {}, plugin.CapSMTP: {}, plugin.CapWeb: {},
	}
	for _, c := range caps {
		if _, ok := allowed[c]; !ok {
			return fmt.Errorf("unknown capability %q", c)
		}
	}
	return nil
}

// HasCapability reports whether entry includes cap.
func (e Entry) HasCapability(cap string) bool {
	return slices.Contains(e.Capabilities, cap)
}

// List returns registered plugin entries.
func (r *Registry) List() []Entry {
	out := make([]Entry, len(r.entries))
	copy(out, r.entries)
	return out
}

// ResolveExe returns an absolute path to the plugin executable.
func (r *Registry) ResolveExe(entry Entry) (string, error) {
	if entry.Exe == "" {
		return "", fmt.Errorf("pluginhost: empty exe for %v", entry.Command)
	}
	if filepath.IsAbs(entry.Exe) {
		return entry.Exe, nil
	}
	local := filepath.Join(r.pluginsDir, entry.Exe)
	if _, err := os.Stat(local); err == nil {
		return local, nil
	}
	if path, err := exec.LookPath(entry.Exe); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("pluginhost: plugin executable not found: %s", entry.Exe)
}

// Op returns the CLI protocol op string (command segments joined by /).
func (e Entry) Op() string {
	return strings.Join(e.Command, "/")
}

// Find returns the CLI-capable entry for a command path like filter/reload.
func (r *Registry) Find(command []string) (Entry, bool) {
	if e, ok := r.findExact(command); ok {
		return e, true
	}
	if len(command) >= 2 {
		if parent, ok := r.findExact(command[:1]); ok && (parent.CliKind == plugin.CliKindAdmin || parent.HasSubcommands()) {
			return parent, true
		}
	}
	return Entry{}, false
}

func (r *Registry) findExact(command []string) (Entry, bool) {
	key := strings.Join(command, "/")
	for _, e := range r.entries {
		if strings.Join(e.Command, "/") == key && e.HasCapability(plugin.CapCLI) {
			return e, true
		}
	}
	return Entry{}, false
}

// FindCLIByPrefix returns CLI entries whose command path equals or extends prefix.
func (r *Registry) FindCLIByPrefix(prefix []string) []Entry {
	if len(prefix) == 0 {
		return nil
	}
	key := strings.Join(prefix, "/")
	var out []Entry
	for _, e := range r.entries {
		if !e.HasCapability(plugin.CapCLI) {
			continue
		}
		cmdKey := strings.Join(e.Command, "/")
		if cmdKey == key || strings.HasPrefix(cmdKey, key+"/") {
			out = append(out, e)
		}
	}
	return out
}

// CLIEntries returns CLI-capable plugins sorted by command path.
func (r *Registry) CLIEntries() []Entry {
	var out []Entry
	for _, e := range r.entries {
		if e.HasCapability(plugin.CapCLI) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Op() < out[j].Op()
	})
	return out
}

// DaemonEntries returns plugins with smtp or web capabilities.
func (r *Registry) DaemonEntries() []Entry {
	var out []Entry
	for _, e := range r.entries {
		if e.HasCapability(plugin.CapSMTP) || e.HasCapability(plugin.CapWeb) {
			out = append(out, e)
		}
	}
	return out
}
