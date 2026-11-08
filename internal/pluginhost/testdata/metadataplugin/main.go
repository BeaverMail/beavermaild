// Minimal plugin that self-describes via metadata probe for registry tests.
package main

import (
	"os"

	"github.com/BeaverMail/beavermaild/plugin"
)

func main() {
	if plugin.IsMetadataProcess() {
		plugin.EmitDescriptor(plugin.Descriptor{
			Command: []string{"widget", "frob"},
			CliFlags: []plugin.CliFlag{
				{Key: "srcdir", Flag: "srcdir", Required: true, Description: "source directory"},
			},
		})
	}
	if len(os.Args) > 1 && os.Args[1] == "fail-probe" {
		os.Exit(1)
	}
	plugin.RunCLI(func(_ plugin.CliRequest, emit *plugin.BatchEmitter) error {
		return emit.EmitDone()
	})
}
