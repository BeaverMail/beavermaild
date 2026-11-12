package mail

// CRLF returns b with every bare LF and bare CR turned into CRLF, the RFC 5322 wire form.
// Messages received with DATA are stored with LF line endings; anything signed or sent
// must be CRLF, or a BDAT peer such as Exim folds the bare LFs into the previous header.
// A bare CR must never leave either (RFC 5321 2.3.8): receivers that take it as a line end
// can be made to see an early end of data (SMTP smuggling, CVE-2023-51764 class).
func CRLF(b []byte) []byte {
	clean := true
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') || c == '\r' && (i+1 == len(b) || b[i+1] != '\n') {
			clean = false
			break
		}
	}
	if clean {
		return b
	}
	out := make([]byte, 0, len(b)+len(b)/32)
	for i, c := range b {
		switch {
		case c == '\r' && (i+1 == len(b) || b[i+1] != '\n'):
			out = append(out, '\r', '\n')
		case c == '\n' && (i == 0 || b[i-1] != '\r'):
			out = append(out, '\r', '\n')
		default:
			out = append(out, c)
		}
	}
	return out
}
