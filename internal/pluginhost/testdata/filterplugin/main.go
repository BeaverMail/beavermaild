// Plugin with filter/reload command for registry prefix tests.
package main

import (
	"github.com/BeaverMail/beavermaild/plugin"
)

func main() {
	if plugin.IsMetadataProcess() {
		plugin.EmitDescriptor(plugin.Descriptor{
			Command: []string{"filter", "reload"},
		})
	}
}
