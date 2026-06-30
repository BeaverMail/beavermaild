package plugin

import "os"

// Plugin process lifecycle env (see docs/plugins.md).
const (
	// EnvPluginMode is set by the host when spawning a daemon-capable plugin persistently.
	// Absent or empty: CLI mode (stdin JSON request, stdout JSONL, process exits).
	EnvPluginMode = "BEAVER_PLUGIN_MODE"
	// PluginModeDaemon is the EnvPluginMode value for beaver serve daemons.
	PluginModeDaemon = "daemon"
	// PluginModeMetadata is the EnvPluginMode value for host descriptor probes.
	PluginModeMetadata = "metadata"
)

// IsDaemonProcess reports whether the current process was started in daemon mode.
func IsDaemonProcess() bool {
	return os.Getenv(EnvPluginMode) == PluginModeDaemon
}

// IsMetadataProcess reports whether the host is probing plugin metadata.
func IsMetadataProcess() bool {
	return os.Getenv(EnvPluginMode) == PluginModeMetadata
}
