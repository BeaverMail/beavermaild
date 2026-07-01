package plugin

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCliRequestVerboseJSON(t *testing.T) {
	t.Parallel()
	line, err := json.Marshal(CliRequest{
		APIVersion:   APIVersion,
		Op:           "import-maildir",
		AccountEmail: "a@b.com",
		Verbose:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(line), `"verbose":true`) {
		t.Fatalf("missing verbose in request JSON: %s", line)
	}
}

func TestCliRequestVerboseOmittedWhenFalse(t *testing.T) {
	t.Parallel()
	line, err := json.Marshal(CliRequest{
		APIVersion:   APIVersion,
		Op:           "import-maildir",
		AccountEmail: "a@b.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(line), `"verbose"`) {
		t.Fatalf("verbose should be omitted when false: %s", line)
	}
}
