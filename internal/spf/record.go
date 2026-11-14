package spf

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// qualifier results (RFC 7208 4.6.2).
var qualifiers = map[byte]Result{'+': Pass, '-': Fail, '~': SoftFail, '?': Neutral}

type mechKind int

const (
	mAll mechKind = iota
	mInclude
	mA
	mMX
	mPTR
	mIP4
	mIP6
	mExists
)

var mechNames = map[string]mechKind{
	"all": mAll, "include": mInclude, "a": mA, "mx": mMX, "ptr": mPTR, "ip4": mIP4, "ip6": mIP6, "exists": mExists,
}

// directive is one mechanism with its qualifier.
type directive struct {
	result Result // what a match returns
	kind   mechKind
	spec   string     // domain-spec ("" = the current <domain>)
	net    *net.IPNet // ip4/ip6
	cidr4  int        // a/mx prefix lengths
	cidr6  int
}

// record is a parsed SPF record (RFC 7208 4.6, 12).
type record struct {
	directives []directive
	redirect   string // domain-spec, "" when absent; ignored when the record has "all" (5.1)
}

// isSPF reports whether a TXT record starts with the version section "v=spf1" (4.5).
func isSPF(txt string) bool {
	return len(txt) >= 6 && strings.EqualFold(txt[:6], "v=spf1") && (len(txt) == 6 || txt[6] == ' ')
}

// parse validates the whole record first: any syntax error is permerror before evaluation (4.6).
func parse(txt string) (*record, error) {
	for i := 0; i < len(txt); i++ {
		if txt[i] < 0x20 || txt[i] > 0x7e {
			return nil, fmt.Errorf("character 0x%02x", txt[i])
		}
	}
	rec := &record{}
	var hasExp bool
	for _, term := range strings.Split(txt[6:], " ") {
		if term == "" {
			continue // 1*SP between terms, *SP at the end
		}
		// A modifier has "=" before any ":" or "/" (4.6.1).
		if eq := strings.IndexByte(term, '='); eq >= 0 && !strings.ContainsAny(term[:eq], ":/") {
			name, value := strings.ToLower(term[:eq]), term[eq+1:]
			if !validName(name) {
				return nil, fmt.Errorf("modifier name %q", name)
			}
			switch name {
			case "redirect", "exp":
				if (name == "redirect" && rec.redirect != "") || (name == "exp" && hasExp) {
					return nil, fmt.Errorf("%s twice", name) // 6: MUST NOT appear more than once
				}
				if !validDomainSpec(value) {
					return nil, fmt.Errorf("%s=%q", name, value)
				}
				if name == "redirect" {
					rec.redirect = value
				} else {
					hasExp = true // exp is not evaluated: we never return explanations (6.2)
				}
			default:
				if !validMacroString(value, true) {
					return nil, fmt.Errorf("modifier %q", term)
				}
			}
			continue
		}
		d, err := parseDirective(term)
		if err != nil {
			return nil, err
		}
		rec.directives = append(rec.directives, d)
	}
	return rec, nil
}

func parseDirective(term string) (directive, error) {
	d := directive{result: Pass, cidr4: 32, cidr6: 128}
	if r, ok := qualifiers[term[0]]; ok {
		d.result, term = r, term[1:]
	}
	end := strings.IndexAny(term, ":/")
	if end < 0 {
		end = len(term)
	}
	kind, ok := mechNames[strings.ToLower(term[:end])]
	if !ok {
		return d, fmt.Errorf("mechanism %q", term)
	}
	d.kind, term = kind, term[end:]
	bad := fmt.Errorf("mechanism %q", term)
	switch kind {
	case mAll:
		if term != "" {
			return d, bad
		}
	case mInclude, mExists:
		if !strings.HasPrefix(term, ":") || !validDomainSpec(term[1:]) {
			return d, bad
		}
		d.spec = term[1:]
	case mPTR:
		if term != "" {
			if !strings.HasPrefix(term, ":") || !validDomainSpec(term[1:]) {
				return d, bad
			}
			d.spec = term[1:]
		}
	case mA, mMX:
		spec, cidr := splitCIDR(term)
		if spec != "" {
			if !strings.HasPrefix(spec, ":") || !validDomainSpec(spec[1:]) {
				return d, bad
			}
			d.spec = spec[1:]
		}
		var err error
		if d.cidr4, d.cidr6, err = parseDualCIDR(cidr); err != nil {
			return d, err
		}
	case mIP4, mIP6:
		if !strings.HasPrefix(term, ":") {
			return d, bad
		}
		addr, bits, hasBits := strings.Cut(term[1:], "/")
		ip := net.ParseIP(addr)
		isV4 := ip != nil && !strings.Contains(addr, ":")
		if ip == nil || isV4 != (kind == mIP4) {
			return d, bad
		}
		size, max := 128, 128
		if isV4 {
			ip, size, max = ip.To4(), 32, 32
		}
		if hasBits {
			n, err := cidrLength(bits, max)
			if err != nil {
				return d, err
			}
			size = n
		}
		d.net = &net.IPNet{IP: ip, Mask: net.CIDRMask(size, len(ip)*8)}
	}
	return d, nil
}

// splitCIDR splits "a:spec/24//64" into ":spec" and "/24//64". A domain-spec may hold any visible
// character, "/" included (7.1), so only a trailing "/digits" and "//digits" are the CIDR part.
func splitCIDR(term string) (string, string) {
	end := len(term)
	if i := strings.LastIndex(term, "//"); i >= 0 && allDigits(term[i+2:]) {
		end = i
	}
	if i := strings.LastIndexByte(term[:end], '/'); i >= 0 && allDigits(term[i+1:end]) {
		end = i
	}
	return term[:end], term[end:]
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// parseDualCIDR reads dual-cidr-length: [ "/" ip4 ] [ "//" ip6 ].
func parseDualCIDR(s string) (int, int, error) {
	v4, v6 := 32, 128
	if s == "" {
		return v4, v6, nil
	}
	var err error
	if v4part, v6part, ok := strings.Cut(s, "//"); ok {
		if v6, err = cidrLength(v6part, 128); err != nil {
			return 0, 0, err
		}
		s = v4part
	}
	if s != "" {
		if !strings.HasPrefix(s, "/") {
			return 0, 0, fmt.Errorf("cidr %q", s)
		}
		if v4, err = cidrLength(s[1:], 32); err != nil {
			return 0, 0, err
		}
	}
	return v4, v6, nil
}

// cidrLength: "0" or a number without a leading zero, at most max.
func cidrLength(s string, max int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > max || (len(s) > 1 && s[0] == '0') || strings.ContainsAny(s, "+-") {
		return 0, fmt.Errorf("cidr length %q", s)
	}
	return n, nil
}

// validName: ALPHA *( ALPHA / DIGIT / "-" / "_" / "." ).
func validName(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !isAlpha(c) && !isDigit(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// validDomainSpec: macro-string domain-end, domain-end = ( "." toplabel [ "." ] ) / macro-expand (7.1).
func validDomainSpec(s string) bool {
	_, endsExpand, err := scanMacros(s, checkLetter(false))
	if err != nil || s == "" {
		return false
	}
	if endsExpand {
		return true
	}
	t := strings.TrimSuffix(s, ".")
	dot := strings.LastIndexByte(t, '.')
	if dot < 0 {
		return false
	}
	return validTopLabel(t[dot+1:])
}

// validTopLabel: ( *alphanum ALPHA *alphanum ) / ( 1*alphanum "-" *( alphanum / "-" ) alphanum ).
func validTopLabel(l string) bool {
	if l == "" {
		return false
	}
	alpha := false
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case isAlpha(c):
			alpha = true
		case isDigit(c):
		case c == '-':
			if i == 0 || i == len(l)-1 {
				return false
			}
		default:
			return false
		}
	}
	return alpha || strings.Contains(l, "-")
}

// validMacroString checks macro-string (7.1). Letters c, r and t are allowed only in explanation
// text; unknown modifiers are not evaluated, so any letter is accepted there.
func validMacroString(s string, anyLetter bool) bool {
	_, _, err := scanMacros(s, checkLetter(anyLetter))
	return err == nil
}

func checkLetter(anyLetter bool) expandFunc {
	return func(letter byte, _ int, _ bool, _ string, _ bool) (string, error) {
		if !anyLetter && strings.IndexByte("slodipvh", letter|0x20) < 0 {
			return "", errors.New("macro letter allowed only in exp")
		}
		return "", nil
	}
}

func isAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
