package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestRFC5258ListExtended checks the LIST-EXTENDED audit fixes (.specs/audit/rfc5258.md).
func TestRFC5258ListExtended(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(c)
	expectPrefix(t, r, "* OK")
	// run sends a command and returns its untagged lines and the tagged reply.
	run := func(tag, line string) ([]string, string) {
		send(t, c, tag+" "+line)
		var out []string
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			l = strings.TrimRight(l, "\r\n")
			if strings.HasPrefix(l, tag+" ") {
				return out, l
			}
			out = append(out, l)
		}
	}
	want := func(tag, line string, lines ...string) {
		t.Helper()
		got, tagged := run(tag, line)
		if !strings.HasPrefix(tagged, tag+" OK") || !slices.Equal(got, lines) {
			t.Fatalf("%s:\n got %q %q\nwant %q", line, got, tagged, lines)
		}
	}
	bad := func(tag, line string) {
		t.Helper()
		if _, tagged := run(tag, line); !strings.HasPrefix(tagged, tag+" BAD") {
			t.Fatalf("%s: %q, want BAD", line, tagged)
		}
	}
	run("l1", "LOGIN alice@localhost beaver")
	for i, cmd := range []string{
		"CREATE Fruit/Apple", "CREATE Veg/Corn", "SUBSCRIBE Veg", "DELETE Veg",
		"CREATE Old/Leaf", "SUBSCRIBE Old/Leaf", "DELETE Old/Leaf", "DELETE Old",
	} {
		if _, tagged := run(fmt.Sprintf("c%d", i), cmd); !strings.Contains(tagged, " OK") {
			t.Fatalf("%s: %q", cmd, tagged)
		}
	}

	// 3: in an extended LIST the empty pattern is no special request and MUST be ignored.
	want("e1", `LIST "Fruit" ("")`)
	want("e2", `LIST "Fruit" ("" "/Apple")`, `* LIST (\HasNoChildren) "/" "Fruit/Apple"`)
	want("e3", `LIST "Fruit" ""`, `* LIST (\Noselect) "/" ""`) // the plain LIST keeps it (RFC 3501 6.3.8)

	// 6: RECURSIVEMATCH needs a list-select-base-opt; SPECIAL-USE is independent (RFC 6154 6).
	bad("o1", `LIST (SPECIAL-USE RECURSIVEMATCH) "" "*"`)
	bad("o2", `LIST (REMOTE RECURSIVEMATCH) "" "*"`)
	want("o3", `LIST (SPECIAL-USE SUBSCRIBED RECURSIVEMATCH) "" "Sent"`, `* LIST (\HasNoChildren \Subscribed \Sent) "/" "Sent"`)

	// 3.1: a subscription outlives its folder (RFC 3501 6.3.4), also when the name is still the
	// parent of folders: LIST (SUBSCRIBED) and LSUB list it, RETURN (SUBSCRIBED) marks it.
	want("s1", `LIST (SUBSCRIBED) "" "Veg"`, `* LIST (\HasChildren \NonExistent \Subscribed) "/" "Veg"`)
	want("s2", `LIST "" "Veg" RETURN (SUBSCRIBED)`, `* LIST (\HasChildren \NonExistent \Subscribed) "/" "Veg"`)
	want("s3", `LSUB "" "Veg"`, `* LSUB (\Noselect) "/" "Veg"`)
	// 3.5 example A2: a missing parent of a subscribed name gets CHILDINFO; LSUB "%" shows it
	// \Noselect (RFC 3501 6.3.9); a plain LIST, which selects nothing, does not show it.
	want("s4", `LIST (SUBSCRIBED RECURSIVEMATCH) "" "Old"`, `* LIST (\HasNoChildren \NonExistent) "/" "Old" ("CHILDINFO" ("SUBSCRIBED"))`)
	want("s5", `LSUB "" "Old"`, `* LSUB (\Noselect) "/" "Old"`)
	want("s6", `LIST "" "Old*"`)
	want("s7", `LIST (SUBSCRIBED) "" "Old/*"`, `* LIST (\HasNoChildren \NonExistent \Subscribed) "/" "Old/Leaf"`)

	// 3: patterns past the server's limit are silently ignored, repeats count once.
	pats := strings.Repeat(`"Fruit" `, 100)
	for i := range 70 {
		pats += fmt.Sprintf(`"zz%d" `, i)
	}
	want("m1", `LIST "" (`+pats+`"Fruit/Apple")`, `* LIST (\HasChildren) "/" "Fruit"`)
	want("m2", `LIST "" (`+strings.Repeat(`"Fruit" `, 100)+`"Fruit/Apple")`,
		`* LIST (\HasChildren) "/" "Fruit"`, `* LIST (\HasNoChildren) "/" "Fruit/Apple"`)

	// RFC 3501 9, RFC 2342: these commands take no argument.
	for i, cmd := range []string{"NAMESPACE x", "NOOP x", "CAPABILITY x", "CHECK x", "UNSELECT x", "IDLE x", "EXPUNGE x", "CLOSE x", "LOGOUT x"} {
		bad(fmt.Sprintf("a%d", i), cmd)
	}
	want("a9", "NAMESPACE", `* NAMESPACE (("" "/")) NIL NIL`)
}
