package plugin_test

import (
	"testing"

	"github.com/BeaverMail/beavermaild/plugin"
)

func TestParseDescriptor(t *testing.T) {
	desc, err := plugin.ParseDescriptor([]byte(`{"api_version":2,"command":["widget","frob"],"cli_flags":[{"key":"srcdir","flag":"srcdir"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(desc.Command) != 2 || desc.CliFlags[0].Key != "srcdir" {
		t.Fatalf("%+v", desc)
	}
}

func TestParseDescriptorVersionMismatch(t *testing.T) {
	_, err := plugin.ParseDescriptor([]byte(`{"api_version":99}`))
	if err == nil {
		t.Fatal("expected version mismatch")
	}
}
