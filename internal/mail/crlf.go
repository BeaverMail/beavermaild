package mail

import "bytes"

// CRLF returns b with every bare LF turned into CRLF, the RFC 5322 wire form.
// Messages received with DATA are stored with LF line endings; anything signed or sent
// must be CRLF, or a BDAT peer such as Exim folds the bare LFs into the previous header.
func CRLF(b []byte) []byte {
	bare := bytes.Count(b, []byte("\n")) - bytes.Count(b, []byte("\r\n"))
	if bare == 0 {
		return b
	}
	out := make([]byte, 0, len(b)+bare)
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, c)
	}
	return out
}
