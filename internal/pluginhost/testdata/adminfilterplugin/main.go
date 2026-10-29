// Admin CLI plugin with bare filter command for dispatch usage tests.
package main

import (
	"github.com/BeaverMail/beavermaild/plugin"
)

func main() {
	if plugin.IsMetadataProcess() {
		plugin.EmitDescriptor(plugin.Descriptor{
			Command:      []string{"filter"},
			Capabilities: []string{plugin.CapCLI},
			CliKind:      plugin.CliKindAdmin,
			CliSubcommands: []plugin.CliSubcommand{
				{Name: "reload", Profile: plugin.CliProfileJob},
			},
		})
	}
}
