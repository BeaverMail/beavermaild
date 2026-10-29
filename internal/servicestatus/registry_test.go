package servicestatus_test

import (
	"testing"

	"github.com/BeaverMail/beavermaild/internal/servicestatus"
)

func TestRegistrySetList(t *testing.T) {
	t.Parallel()
	r := servicestatus.New()
	r.Set(servicestatus.Entry{ID: "smtp_inbound", Name: "SMTP", Listen: ":25", State: servicestatus.StateUp})
	r.Set(servicestatus.Entry{ID: "imap", Name: "IMAP", Listen: ":143", State: servicestatus.StateError, Error: "bind"})
	list := r.List()
	if len(list) != 2 {
		t.Fatalf("%v", list)
	}
	if list[0].ID != "imap" || list[1].ID != "smtp_inbound" {
		t.Fatalf("order %v", list)
	}
	if list[0].Error != "bind" || list[1].State != servicestatus.StateUp {
		t.Fatalf("%+v", list)
	}
}
