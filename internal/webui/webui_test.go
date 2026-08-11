package webui_test

import (
	"io/fs"
	"testing"

	"github.com/BeaverMail/beaver/internal/webui"
)

// TestEmbedIncludesIndex checks go:embed always ships at least index.html.
func TestEmbedIncludesIndex(t *testing.T) {
	t.Parallel()
	if !webui.Enabled() {
		t.Fatal("expected Enabled")
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
