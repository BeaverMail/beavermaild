package plugin_test

import (
	"testing"

	"github.com/BeaverMail/beaver/plugin"
)

func TestIsDaemonProcess(t *testing.T) {
	t.Setenv(plugin.EnvPluginMode, "")
	if plugin.IsDaemonProcess() {
		t.Fatal("expected cli mode")
	}
	t.Setenv(plugin.EnvPluginMode, plugin.PluginModeDaemon)
	if !plugin.IsDaemonProcess() {
		t.Fatal("expected daemon mode")
	}
}

func TestIsMetadataProcess(t *testing.T) {
	t.Setenv(plugin.EnvPluginMode, "")
	if plugin.IsMetadataProcess() {
		t.Fatal("expected cli mode")
	}
	t.Setenv(plugin.EnvPluginMode, plugin.PluginModeMetadata)
	if !plugin.IsMetadataProcess() {
		t.Fatal("expected metadata mode")
	}
}
