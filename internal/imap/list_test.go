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

func TestParseListArg(t *testing.T) {
	t.Parallel()

	ref, pat, ok := parseListArg(`"" "*"`)
	if !ok || ref != "" || pat != "*" {
		t.Fatalf(`parse star: ref=%q pat=%q ok=%v`, ref, pat, ok)
	}
	ref, pat, ok = parseListArg(`"" "Sent"`)
	if !ok || pat != "Sent" {
		t.Fatalf(`parse sent: %q %q`, ref, pat)
	}
}
