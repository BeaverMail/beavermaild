// Plugin with filter/list command for registry prefix tests.
package main

import (
	"github.com/BeaverMail/beaver/plugin"
)

func main() {
	if plugin.IsMetadataProcess() {
		plugin.EmitDescriptor(plugin.Descriptor{
			Command: []string{"filter", "list"},
		})
	}
}
