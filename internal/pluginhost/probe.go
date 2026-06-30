// Plugin metadata probe: exec binary with BEAVER_PLUGIN_MODE=metadata.
package pluginhost

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/BeaverMail/beaver/plugin"
)

const probeTimeout = 5 * time.Second

type cachedDescriptor struct {
	modUnix int64
	desc    plugin.Descriptor
	ok      bool
}

var descriptorCache sync.Map

// probePluginDescriptor asks the plugin binary for its Descriptor JSON line.
// Unsupported or failing probes return ok=false without failing registry load.
func probePluginDescriptor(exePath string) (plugin.Descriptor, bool, error) {
	info, err := os.Stat(exePath)
	if err != nil {
		return plugin.Descriptor{}, false, err
	}
	modUnix := info.ModTime().Unix()
	if v, hit := descriptorCache.Load(exePath); hit {
		c := v.(cachedDescriptor)
		if c.modUnix == modUnix {
			return c.desc, c.ok, nil
		}
	}

	desc, ok, err := runDescriptorProbe(exePath)
	if err != nil {
		return plugin.Descriptor{}, false, err
	}
	descriptorCache.Store(exePath, cachedDescriptor{modUnix: modUnix, desc: desc, ok: ok})
	return desc, ok, nil
}

func runDescriptorProbe(exePath string) (plugin.Descriptor, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, exePath)
	cmd.Env = append(os.Environ(), plugin.EnvPluginMode+"="+plugin.PluginModeMetadata)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return plugin.Descriptor{}, false, nil
		}
		return plugin.Descriptor{}, false, nil
	}
	line := bytes.TrimSpace(stdout.Bytes())
	if len(line) == 0 {
		return plugin.Descriptor{}, false, nil
	}
	desc, err := plugin.ParseDescriptor(line)
	if err != nil {
		return plugin.Descriptor{}, false, fmt.Errorf("pluginhost: %s descriptor: %w", filepath.Base(exePath), err)
	}
	return desc, true, nil
}

// ProbePluginDescriptorForTest exposes metadata probe for integration tests.
func ProbePluginDescriptorForTest(exePath string) (plugin.Descriptor, bool, error) {
	return probePluginDescriptor(exePath)
}
