// RFC 5256 base subject, shared by SORT SUBJECT and THREAD REFERENCES.
package mail

import "strings"

// BaseSubject extracts the RFC 5256 section 2.1 base subject: encoded words decoded, white space
// collapsed, "(fwd)" trailers, "Re:"/"Fw:"/"Fwd:" leaders, "[blob]" prefixes and "[fwd: ...]"
// wrappers removed. isReplyOrFwd reports whether any reply/forward marker was removed.
func BaseSubject(subject string) (base string, isReplyOrFwd bool) {
	if d, err := headerDecoder.DecodeHeader(subject); err == nil {
		subject = d
	}
	s := strings.Join(strings.Fields(subject), " ")
	for {
		// (2) subj-trailer: "(fwd)" and white space at the end.
		for {
			t := strings.TrimRight(s, " ")
			if len(t) >= 5 && strings.EqualFold(t[len(t)-5:], "(fwd)") {
				s, isReplyOrFwd = t[:len(t)-5], true
				continue
			}
			s = t
			break
		}
		// (3)-(5) subj-leader and subj-blob prefixes; a blob stays if nothing would be left.
		for {
			s = strings.TrimLeft(s, " ")
			if rest, ok := cutRefwd(s); ok {
				s, isReplyOrFwd = rest, true
				continue
			}
			if rest, ok := cutBlob(s); ok && strings.TrimSpace(rest) != "" {
				s = rest
				continue
			}
			break
		}
		// (6) "[fwd:" subject "]" wrapper.
		if len(s) >= 6 && strings.EqualFold(s[:5], "[fwd:") && s[len(s)-1] == ']' {
			s, isReplyOrFwd = s[5:len(s)-1], true
			continue
		}
		return s, isReplyOrFwd
	}
}

// cutRefwd removes a leading subj-refwd: ("re" / "fw" ["d"]) *WSP [subj-blob] ":".
func cutRefwd(s string) (string, bool) {
	lower := strings.ToLower(s)
	var rest string
	switch {
	case strings.HasPrefix(lower, "re"):
		rest = s[2:]
	case strings.HasPrefix(lower, "fwd"):
		rest = s[3:]
	case strings.HasPrefix(lower, "fw"):
		rest = s[2:]
	default:
		return s, false
	}
	rest = strings.TrimLeft(rest, " ")
	if r, ok := cutBlob(rest); ok {
		rest = r
	}
	if !strings.HasPrefix(rest, ":") {
		return s, false
	}
	return rest[1:], true
}

// cutBlob removes a leading subj-blob: "[" *BLOBCHAR "]" *WSP, BLOBCHAR excluding "[" and "]".
func cutBlob(s string) (string, bool) {
	if !strings.HasPrefix(s, "[") {
		return s, false
	}
	end := strings.IndexAny(s[1:], "[]")
	if end < 0 || s[1+end] != ']' {
		return s, false
	}
	return strings.TrimLeft(s[end+2:], " "), true
}
