package webui_test

import (
	"io/fs"
	"testing"

	"github.com/BeaverMail/beaver/internal/webui"
)

// TestEmbedIncludesIndex checks the UI is enabled only when the SPA build (index.html) is embedded.
func TestEmbedIncludesIndex(t *testing.T) {
	t.Parallel()
	if !webui.Enabled() {
		t.Skip("no SPA build in internal/webui/dist (run make web-build)")
	}
	root, ok := webui.Assets()
	if !ok || root == nil {
		t.Fatal("expected assets")
	}
	data, err := fs.ReadFile(root, "index.html")
	if err != nil || len(data) == 0 {
		t.Fatalf("index.html: %v", err)
	}
}
