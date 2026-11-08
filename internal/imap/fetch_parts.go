// IMAP FETCH helpers for partial RFC 822 header fields in BODY sections.
package imap

import (
	"bytes"
	"strings"
)

// extractHeaderFields returns the requested header lines exactly as stored (original order,
// name case and folding) followed by the delimiting blank line, per RFC 3501 HEADER.FIELDS.
func extractHeaderFields(raw []byte, fields []string) []byte {
	want := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		want[strings.ToUpper(strings.TrimSpace(f))] = struct{}{}
	}
	hdr, _ := splitHeaderBody(raw)
	var out []byte
	keep := false
	for len(hdr) > 0 {
		line := hdr
		if i := bytes.IndexByte(hdr, '\n'); i >= 0 {
			line = hdr[:i+1]
		}
		hdr = hdr[len(line):]
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			break // blank line ends the header
		}
		if line[0] != ' ' && line[0] != '\t' { // not a folded continuation: a new field starts
			name, _, ok := bytes.Cut(line, []byte(":"))
			_, wanted := want[strings.ToUpper(strings.TrimSpace(string(name)))]
			keep = ok && wanted
		}
		if keep {
			out = append(out, line...)
			if line[len(line)-1] != '\n' {
				out = append(out, '\r', '\n')
			}
		}
	}
	return append(out, '\r', '\n')
}
