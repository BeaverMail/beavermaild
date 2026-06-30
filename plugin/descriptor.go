// Plugin self-description for host discovery (metadata probe mode).
package plugin

import (
	"encoding/json"
	"fmt"
	"os"
)

// CliFlag declares a dedicated CLI flag the host maps into CliRequest.params.
type CliFlag struct {
	Key         string `json:"key"`
	Flag        string `json:"flag"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description,omitempty"`
}

// Descriptor is the JSON line a plugin prints in metadata probe mode.
type Descriptor struct {
	APIVersion   uint32   `json:"api_version"`
	Command      []string `json:"command,omitempty"`
	CliFlags     []CliFlag `json:"cli_flags,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// EmitDescriptor writes the descriptor JSON line to stdout and exits 0.
func EmitDescriptor(desc Descriptor) {
	if desc.APIVersion == 0 {
		desc.APIVersion = APIVersion
	}
	if len(desc.Capabilities) == 0 {
		desc.Capabilities = []string{CapCLI}
	}
	b, err := json.Marshal(desc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin: descriptor: %v\n", err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(append(b, '\n'))
	os.Exit(0)
}

// ParseDescriptor decodes one descriptor JSON line from plugin stdout.
func ParseDescriptor(line []byte) (Descriptor, error) {
	var desc Descriptor
	if err := json.Unmarshal(line, &desc); err != nil {
		return Descriptor{}, err
	}
	if desc.APIVersion != 0 && desc.APIVersion != APIVersion {
		return Descriptor{}, fmt.Errorf("plugin: API version mismatch host=%d plugin=%d", APIVersion, desc.APIVersion)
	}
	return desc, nil
}
