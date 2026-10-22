package imap

import "testing"

func TestParseLogin(t *testing.T) {
	for _, tc := range []struct{ arg, user, pass string }{
		{`alice@example.org secret`, "alice@example.org", "secret"},
		{`alice@example.org "correct horse"`, "alice@example.org", "correct horse"},
		{`"alice@example.org" "correct horse"`, "alice@example.org", "correct horse"},
		{`"alice@example.org" secret`, "alice@example.org", "secret"},
		{`alice "a\"b\\c"`, "alice", `a"b\c`},
	} {
		user, pass, ok := parseLogin(tc.arg)
		if !ok || user != tc.user || pass != tc.pass {
			t.Errorf("parseLogin(%q) = %q, %q, %v; want %q, %q", tc.arg, user, pass, ok, tc.user, tc.pass)
		}
	}
	for _, bad := range []string{"", "alice", `"alice`, `alice "unterminated`} {
		if _, _, ok := parseLogin(bad); ok {
			t.Errorf("parseLogin(%q) accepted", bad)
		}
	}
}
