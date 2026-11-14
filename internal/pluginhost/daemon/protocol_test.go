package daemon

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/smtp"
)

// RFC 8617 audit X5: the plugin needs the newest ARC sealer to decide whether to trust a chain.
func TestEncodeFilterRequestARCSealer(t *testing.T) {
	out := encodeFilterRequest(smtp.FilterRequest{Auth: &smtp.FilterAuth{ARC: "pass", ARCSealer: "lists.example.org"}})
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"arc":"pass","arc_sealer":"lists.example.org"`) {
		t.Fatalf("%s", b)
	}
}
