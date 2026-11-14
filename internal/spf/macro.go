package spf

import (
	"errors"
	"strings"
)

// expandFunc returns the value of one macro: letter as written (upper case asks for URL escaping),
// digits (0 = all parts), reverse, delimiters ("" = "."), url.
type expandFunc func(letter byte, digits int, reverse bool, delims string, url bool) (string, error)

// scanMacros walks a macro-string (RFC 7208 7.1) and builds its expansion with fn. endsExpand
// tells whether the last token was a macro-expand (a domain-spec may end with one).
func scanMacros(s string, fn expandFunc) (out string, endsExpand bool, err error) {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c != '%' {
			if c < 0x21 || c > 0x7e {
				return "", false, errors.New("macro-string: character")
			}
			b.WriteByte(c)
			i++
			endsExpand = false
			continue
		}
		if i+1 >= len(s) {
			return "", false, errors.New("macro-string: lone %") // 7.3
		}
		endsExpand = true
		switch s[i+1] {
		case '%':
			b.WriteByte('%')
			i += 2
			continue
		case '_':
			b.WriteByte(' ')
			i += 2
			continue
		case '-':
			b.WriteString("%20")
			i += 2
			continue
		case '{':
		default:
			return "", false, errors.New("macro-string: % not followed by {, %, - or _")
		}
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return "", false, errors.New("macro-string: unclosed %{")
		}
		body := s[i+2 : i+end] // letter transformers *delimiter
		i += end + 1
		if body == "" || strings.IndexByte("slodiphcrtv", body[0]|0x20) < 0 {
			return "", false, errors.New("macro-string: letter")
		}
		letter, rest := body[0], body[1:]
		digits := 0
		j := 0
		for j < len(rest) && isDigit(rest[j]) {
			j++
		}
		if j > 0 {
			if rest[0] == '0' { // "If a DIGIT is specified, the value MUST be nonzero"
				return "", false, errors.New("macro-string: zero or padded digits")
			}
			// *DIGIT has no upper bound; past 1000 (beyond any domain's 127 labels) it means all parts.
			for _, d := range rest[:j] {
				digits = min(digits*10+int(d-'0'), 1000)
			}
		}
		rest = rest[j:]
		reverse := false
		if rest != "" && (rest[0] == 'r' || rest[0] == 'R') {
			reverse, rest = true, rest[1:]
		}
		if strings.Trim(rest, ".-+,/_=") != "" {
			return "", false, errors.New("macro-string: delimiter")
		}
		v, err := fn(letter, digits, reverse, rest, letter >= 'A' && letter <= 'Z')
		if err != nil {
			return "", false, err
		}
		b.WriteString(v)
	}
	return b.String(), endsExpand, nil
}

// transform applies the transformers of 7.3: split on the delimiters, reverse, keep the
// right-most digits parts, join with ".".
func transform(value string, digits int, reverse bool, delims string) string {
	if delims == "" {
		delims = "."
	}
	parts := splitAny(value, delims)
	if reverse {
		for l, r := 0, len(parts)-1; l < r; l, r = l+1, r-1 {
			parts[l], parts[r] = parts[r], parts[l]
		}
	}
	if digits > 0 && digits < len(parts) {
		parts = parts[len(parts)-digits:]
	}
	return strings.Join(parts, ".")
}

// splitAny splits on every delimiter character, keeping empty parts (7.3: no special treatment of
// leading, trailing or consecutive delimiters).
func splitAny(s, delims string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(delims, s[i]) >= 0 {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// urlEscape escapes everything outside the RFC 3986 unreserved set (7.3).
func urlEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlpha(c) || isDigit(c) || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// truncate253 drops left-most labels until the name fits in 253 characters (7.3).
func truncate253(name string) string {
	for len(name) > 253 {
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return name // one label over 253: invalid, rejected by the caller
		}
		name = name[i+1:]
	}
	return name
}
