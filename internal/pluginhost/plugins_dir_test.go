package pluginhost_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beaver/internal/pluginhost"
)

func TestPluginsDirFromConfigPathWithoutConfigFile(t *testing.T) {
	dir := t.TempDir()
	got := pluginhost.PluginsDirFromConfigPath(filepath.Join(dir, "data", "config.json"))
	want := filepath.Join(dir, "data", "plugins")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestPluginsDirFromConfigPathUsesDataDir(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	body := `{"data_dir":"` + filepath.Join(dir, "maildata") + `"}`
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := pluginhost.PluginsDirFromConfigPath(cfgPath)
	want := filepath.Join(dir, "maildata", "plugins")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
