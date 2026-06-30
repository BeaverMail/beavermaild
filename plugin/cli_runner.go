package plugin

import (
	"fmt"
	"os"
)

// CLIHandler runs one CLI job and emits JSONL events via emit.
type CLIHandler func(req CliRequest, emit *BatchEmitter) error

// RunCLI reads stdin request, runs handler, writes protocol to stdout.
func RunCLI(handler CLIHandler) {
	req, err := ReadCliRequest(os.Stdin)
	if err != nil {
		_ = NewBatchEmitter(os.Stdout, DefaultBatchSize).EmitError(err.Error())
		os.Exit(1)
	}
	emit := NewBatchEmitter(os.Stdout, BatchSizeFromEnv())
	if err := handler(req, emit); err != nil {
		_ = emit.EmitError(err.Error())
		os.Exit(1)
	}
}

// CheckAPIVersion validates host API version when non-zero.
func CheckAPIVersion(hostVersion uint32) error {
	if hostVersion != 0 && hostVersion != APIVersion {
		return fmt.Errorf("plugin: API version mismatch host=%d plugin=%d", hostVersion, APIVersion)
	}
	return nil
}
