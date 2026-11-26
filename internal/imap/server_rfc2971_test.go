package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestRFC2971ID: ID works in every state and answers BAD to arguments that are no
// id_params_list (RFC 2971 3.1, 4): NIL, or field-value pairs, the field a string, the value a
// string or NIL.
func TestRFC2971ID(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	expectPrefix(t, r, "* OK")
	for i, arg := range []string{`NIL`, `()`, `("name" "x" "version" NIL)`, "({4+}\r\nname {1+}\r\nx)"} {
		send(t, c, fmt.Sprintf("g%d ID %s", i, arg))
		expectPrefix(t, r, `* ID ("name" "BeaverMail")`)
		expectPrefix(t, r, fmt.Sprintf("g%d OK", i))
	}
	for i, arg := range []string{`(foo bar)`, `("a")`, `("a" "b" "c")`, `(NIL "b")`, `("a" "b")junk)`, `("a" ("b"))`, `(`, ``, `NIL x`} {
		send(t, c, fmt.Sprintf("b%d ID %s", i, arg))
		expectPrefix(t, r, fmt.Sprintf("b%d BAD", i))
	}
}
