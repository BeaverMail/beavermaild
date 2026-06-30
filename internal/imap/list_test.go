package imap

import "testing"

func TestCompileListPattern(t *testing.T) {
	t.Parallel()

	all := compileListPattern("*")
	if !all("INBOX") || !all("Sent") || !all("Custom") {
		t.Fatal("star pattern")
	}

	sent := compileListPattern("Sent")
	if !sent("Sent") || sent("Drafts") {
		t.Fatal("literal pattern")
	}

	inbox := compileListPattern("INBOX")
	if !inbox("INBOX") {
		t.Fatal("inbox case")
	}

	prefix := compileListPattern("D*")
	if !prefix("Drafts") || prefix("Sent") {
		t.Fatal("prefix wildcard")
	}
}

func TestParseListOptions(t *testing.T) {
	t.Parallel()

	opt, ok := parseListOptions(`"" "*"`)
	if !ok || opt.ref != "" || opt.pattern != "*" || opt.subscribedOnly {
		t.Fatalf(`parse star: %+v ok=%v`, opt, ok)
	}

	opt, ok = parseListOptions(`(SUBSCRIBED) "" "*"`)
	if !ok || !opt.subscribedOnly || opt.pattern != "*" {
		t.Fatalf(`parse subscribed: %+v ok=%v`, opt, ok)
	}

	opt, ok = parseListOptions(`"" "*" RETURN (SUBSCRIBED CHILDREN)`)
	if !ok || opt.subscribedOnly || !opt.markSubscribed || opt.pattern != "*" {
		t.Fatalf(`parse return subscribed: %+v ok=%v`, opt, ok)
	}
}

func TestMailboxHasChildren(t *testing.T) {
	t.Parallel()

	names := []string{"INBOX", "Work", "Work/Projects", "Archive"}
	if !mailboxHasChildren("Work", names) {
		t.Fatal("Work should have children")
	}
	if mailboxHasChildren("Work/Projects", names) {
		t.Fatal("leaf should have no children")
	}
	if mailboxHasChildren("INBOX", names) {
		t.Fatal("INBOX has no child mailboxes in this set")
	}
	if !mailboxHasChildren("work", names) {
		t.Fatal("case-insensitive parent should see children")
	}
}
