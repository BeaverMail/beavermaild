package imap

import "testing"

func TestValidIMAPTag(t *testing.T) {
	t.Parallel()

	if !validIMAPTag("a1") || !validIMAPTag("tag-01") {
		t.Fatal("valid tags")
	}
	if validIMAPTag("") || validIMAPTag("a\r") || validIMAPTag("a\n") {
		t.Fatal("invalid tags accepted")
	}
}

func TestMailboxNameFromArg(t *testing.T) {
	t.Parallel()

	name, err := mailboxNameFromArg(`"Archive"`)
	if err != nil || name != "Archive" {
		t.Fatalf("name %q err %v", name, err)
	}
	if _, err := mailboxNameFromArg(`"bad`+"\r"+`name"`); err == nil {
		t.Fatal("expected reject")
	}
}
