package mail

// CRLF returns b in the RFC 5322 wire form for sending: bare CR handled as in BareCR, then every
// bare LF turned into CRLF. Messages received with DATA are stored with LF line endings; anything
// signed or sent must be CRLF, or a BDAT peer such as Exim folds the bare LFs into the previous
// header. A bare CR must never leave (RFC 5321 2.3.8): receivers that take it as a line end can be
// made to see an early end of data (SMTP smuggling, CVE-2023-51764 class).
func CRLF(b []byte) []byte {
	return wireForm(BareCR(b))
}

// BareCR returns b with no CR left except before LF, as Exim does (receive.c): in the header
// block a bare CR becomes LF SP, a folded continuation, so it can neither end the header nor start
// a forged field; in the body it becomes LF, a line end. Turning it into CRLF everywhere made
// "\r\r\n" an empty line, which inside the header ended it early.
func BareCR(b []byte) []byte {
	bare := false
	for i, c := range b {
		if c == '\r' && (i+1 == len(b) || b[i+1] != '\n') {
			bare = true
			break
		}
	}
	if !bare {
		return b
	}
	out := make([]byte, 0, len(b)+len(b)/64+1)
	inHeader, lineStart := true, true
	for i, c := range b {
		if c == '\r' && (i+1 == len(b) || b[i+1] != '\n') {
			if inHeader {
				out = append(out, '\n', ' ')
				lineStart = false
				continue
			}
			c = '\n'
		}
		if c == '\n' {
			if inHeader && lineStart {
				inHeader = false // the empty line ending the header block
			}
			lineStart = true
		} else if c != '\r' {
			lineStart = false
		}
		out = append(out, c)
	}
	return out
}
