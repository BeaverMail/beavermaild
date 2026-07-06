// CLI profile resolution from plugin registry entries.
package pluginhost

import (
	"fmt"
	"strings"

	"github.com/BeaverMail/beaver/plugin"
)

// HasSubcommands reports whether the plugin declares admin subcommands.
func (e Entry) HasSubcommands() bool {
	return len(e.CliSubcommands) > 0
}

// OpForCommand returns the protocol op string for argv command segments.
func (e Entry) OpForCommand(cmd []string) string {
	if e.HasSubcommands() && len(cmd) > len(e.Command) {
		return strings.Join(cmd, "/")
	}
	return e.Op()
}

// ProfileForCommand returns the host CLI profile for argv command segments.
func (e Entry) ProfileForCommand(cmd []string) (string, error) {
	if e.HasSubcommands() {
		if len(cmd) <= len(e.Command) {
			return "", fmt.Errorf("subcommand required")
		}
		name := cmd[len(e.Command)]
		for _, sc := range e.CliSubcommands {
			if sc.Name == name {
				if sc.Profile == "" {
					return plugin.CliProfileJob, nil
				}
				return sc.Profile, nil
			}
		}
		return "", fmt.Errorf("unknown subcommand %q", name)
	}
	if e.CliKind == plugin.CliKindAdmin {
		return plugin.CliProfileJob, nil
	}
	return plugin.CliProfileIngest, nil
}

// RequiresAccount reports whether profile needs -account on the host CLI.
func RequiresAccount(profile string) bool {
	switch profile {
	case plugin.CliProfileIngest, plugin.CliProfileAccountScan:
		return true
	default:
		return false
	}
}
