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
	if !ok || opt.ref != "" || opt.patterns[0] != "*" || opt.subscribedOnly {
		t.Fatalf(`parse star: %+v ok=%v`, opt, ok)
	}

	opt, ok = parseListOptions(`(SUBSCRIBED) "" "*"`)
	if !ok || !opt.subscribedOnly || opt.patterns[0] != "*" {
		t.Fatalf(`parse subscribed: %+v ok=%v`, opt, ok)
	}

	opt, ok = parseListOptions(`"" "*" RETURN (SUBSCRIBED CHILDREN)`)
	if !ok || opt.subscribedOnly || !opt.markSubscribed || opt.patterns[0] != "*" {
		t.Fatalf(`parse return subscribed: %+v ok=%v`, opt, ok)
	}

	opt, ok = parseListOptions(`(SUBSCRIBED RECURSIVEMATCH) "" ("INBOX" Sent "A B") RETURN (SPECIAL-USE)`)
	if !ok || !opt.recursiveMatch || !opt.subscribedOnly || len(opt.patterns) != 3 || opt.patterns[1] != "Sent" || opt.patterns[2] != "A B" {
		t.Fatalf(`parse extended: %+v ok=%v`, opt, ok)
	}

	opt, ok = parseListOptions(`(SPECIAL-USE) "" "*" RETURN ()`)
	if !ok || !opt.specialUseOnly || !opt.extended {
		t.Fatalf(`parse special-use: %+v ok=%v`, opt, ok)
	}

	for _, bad := range []string{
		`(RECURSIVEMATCH) "" "*"`,
		`(REMOTE RECURSIVEMATCH) "" "*"`,
		`(BOGUS) "" "*"`,
		`"" "*" RETURN (BOGUS)`,
		`"" "*" RETURN SUBSCRIBED`,
		`"" ()`,
		`"" ("INBOX"`,
		`"" "*" junk`,
	} {
		if _, ok := parseListOptions(bad); ok {
			t.Errorf("parseListOptions(%s) accepted", bad)
		}
	}
}

func TestMailboxHasChildren(t *testing.T) {
	t.Parallel()

	parents := newParentSet([]string{"INBOX", "Work", "Work/Projects", "Archive", "Deep/a/b"})
	if !parents.has("Work") {
		t.Fatal("Work should have children")
	}
	if parents.has("Work/Projects") {
		t.Fatal("leaf should have no children")
	}
	if parents.has("INBOX") {
		t.Fatal("INBOX has no child mailboxes in this set")
	}
	if !parents.has("work") {
		t.Fatal("case-insensitive parent should see children")
	}
	if !parents.has("Deep") || !parents.has("Deep/a") || parents.has("Deep/a/b") {
		t.Fatal("every superior of a nested folder has children")
	}
}
