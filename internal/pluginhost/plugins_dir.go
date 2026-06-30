// Plugin install path resolution relative to beaver -c.
package pluginhost

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/BeaverMail/beaver/internal/config"
)

// PluginsDirFromConfigPath resolves data/plugins from a config file path.
// When config.json is missing, uses the config file directory (e.g. data/plugins for data/config.json).
func PluginsDirFromConfigPath(configPath string) string {
	if cfg, err := config.Load(configPath); err == nil {
		if d := strings.TrimSpace(cfg.DataDir); d != "" {
			return filepath.Join(d, "plugins")
		}
	}
	if v := os.Getenv("BEAVER_DATA_DIR"); v != "" {
		return filepath.Join(v, "plugins")
	}
	if dir := filepath.Dir(configPath); dir != "" && dir != "." {
		return filepath.Join(dir, "plugins")
	}
	return filepath.Join(config.DefaultDataDir, "plugins")
}
