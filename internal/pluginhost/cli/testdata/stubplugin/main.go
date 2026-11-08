// Minimal CLI plugin used only by pluginhost integration tests.
package main

import (
	"github.com/BeaverMail/beavermaild/plugin"
)

func main() {
	if plugin.IsMetadataProcess() {
		plugin.EmitDescriptor(plugin.Descriptor{
			Command: []string{"test", "ingest"},
		})
	}
	plugin.RunCLI(runStub)
}

func runStub(_ plugin.CliRequest, emit *plugin.BatchEmitter) error {
	raw := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: hi\r\n\r\nbody\r\n")
	path, err := plugin.WriteTempMessage(raw)
	if err != nil {
		return err
	}
	hash, err := plugin.HashFile(path)
	if err != nil {
		return err
	}
	if err := emit.Add(plugin.BatchMessage{
		IMAPName:    "INBOX",
		RawPath:     path,
		BlobHashHex: hash,
	}); err != nil {
		return err
	}
	return emit.EmitDone()
}
