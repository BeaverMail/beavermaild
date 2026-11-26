package mail

import (
	"io"
	"mime"
	"net/mail"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
)

// headerDecoder decodes RFC 2047 encoded-words in any charset the WHATWG index knows (as the
// antispam plugin does), not only the stdlib's UTF-8, ISO-8859-1 and US-ASCII.
var headerDecoder = &mime.WordDecoder{CharsetReader: func(charset string, r io.Reader) (io.Reader, error) {
	e, err := htmlindex.Get(charset)
	if err != nil || e == encoding.Replacement {
		return nil, err
	}
	return e.NewDecoder().Reader(r), nil
}}

// addressParser parses address lists with headerDecoder for display names.
var addressParser = mail.AddressParser{WordDecoder: headerDecoder}

// EnvelopeAddress is one address of an IMAP ENVELOPE address list (RFC 3501 7.4.2): a mailbox
// (Mailbox and Host set), a group start (Mailbox is the group name, Host empty), a group end, or
// an address that could not be read (all empty). Name is the decoded display name.
type EnvelopeAddress struct {
	Name, Route, Mailbox, Host string
	GroupEnd                   bool
}

// ParseAddressField reads an address header as IMAP ENVELOPE and SORT see it: RFC 822 group
// syntax ("name: a@b, c@d;") becomes a group start, the members, and a group end, as RFC 3501
// requires; groups are not expanded away. SORT keys derive from this same list (RFC 5256 3,
// RFC 5957 4).
func ParseAddressField(value string) []EnvelopeAddress {
	var out []EnvelopeAddress
	var cur strings.Builder
	flush := func() {
		for _, a := range parseAddressList(cur.String()) {
			out = append(out, envelopeMailbox(a))
		}
		cur.Reset()
	}
	inQuote, inGroup := false, false
	angle, comment := 0, 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '\\' && i+1 < len(value):
			cur.WriteByte(c)
			i++
			c = value[i]
		case comment > 0:
			if c == '(' {
				comment++
			} else if c == ')' {
				comment--
			}
		case inQuote:
			inQuote = c != '"'
		case c == '"':
			inQuote = true
		case c == '(':
			comment++
		case c == '<':
			angle++
		case c == '>' && angle > 0:
			angle--
		case angle == 0 && c == ':' && !inGroup:
			out = append(out, EnvelopeAddress{Mailbox: strings.Trim(strings.TrimSpace(cur.String()), `"`)})
			cur.Reset()
			inGroup = true
			continue
		case angle == 0 && c == ';' && inGroup:
			flush()
			out = append(out, EnvelopeAddress{GroupEnd: true})
			inGroup = false
			continue
		case angle == 0 && c == ',':
			flush()
			continue
		}
		cur.WriteByte(c)
	}
	flush()
	if inGroup {
		out = append(out, EnvelopeAddress{GroupEnd: true})
	}
	return out
}

// envelopeMailbox splits one parsed address into the ENVELOPE slots.
func envelopeMailbox(a *mail.Address) EnvelopeAddress {
	addr := strings.TrimSpace(a.Address)
	// An obsolete source route ("<@route:user@domain>", RFC 822) goes in the adl slot.
	var route string
	if strings.HasPrefix(addr, "@") {
		if r, rest, ok := strings.Cut(addr, ":"); ok {
			route, addr = r, rest
		}
	}
	// The last "@": a quoted local part may hold one ("\"a@b\"@c" is the mailbox a@b at host c).
	at := strings.LastIndexByte(addr, '@')
	mailbox, host := addr[:max(at, 0)], addr[at+1:]
	if at < 0 || mailbox == "" || host == "" {
		return EnvelopeAddress{}
	}
	return EnvelopeAddress{Name: decodeWords(strings.TrimSpace(a.Name)), Route: route, Mailbox: mailbox, Host: host}
}

// decodeWords decodes the encoded-words a fallback parse left in a display name; text that does
// not decode stays as it is.
func decodeWords(s string) string {
	if d, err := headerDecoder.DecodeHeader(s); err == nil {
		return d
	}
	return s
}

// parseAddressList parses one RFC 822 address list (no group syntax), skipping empty entries.
func parseAddressList(s string) []*mail.Address {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	addrs, err := addressParser.ParseList(s)
	if err != nil {
		if a, err := addressParser.Parse(s); err == nil {
			return []*mail.Address{a}
		}
		return parseAddressListFallback(s)
	}
	out := make([]*mail.Address, 0, len(addrs))
	for _, a := range addrs {
		if strings.TrimSpace(a.Address) == "" {
			continue
		}
		out = append(out, a)
	}
	if len(out) > 0 {
		return out
	}
	return parseAddressListFallback(s)
}

// parseAddressListFallback extracts angle-addr tokens when the stdlib parser fails.
func parseAddressListFallback(s string) []*mail.Address {
	var out []*mail.Address
	for s != "" {
		s = strings.TrimLeft(s, " \t,")
		if s == "" {
			break
		}
		if i := strings.IndexByte(s, '<'); i >= 0 {
			j := strings.IndexByte(s[i:], '>')
			if j < 0 {
				break
			}
			j += i
			addr := strings.TrimSpace(s[i+1 : j])
			name := strings.TrimSpace(strings.Trim(s[:i], `"`))
			if addr != "" {
				out = append(out, &mail.Address{Name: name, Address: addr})
			}
			s = s[j+1:]
			continue
		}
		if at := strings.IndexByte(s, '@'); at > 0 {
			end := strings.IndexAny(s[at:], ",; \t")
			addr := strings.TrimSpace(s)
			if end >= 0 {
				addr = strings.TrimSpace(s[:at+end])
				s = s[at+end:]
			} else {
				s = ""
			}
			if a, err := addressParser.Parse(addr); err == nil {
				out = append(out, a)
			}
			continue
		}
		// A bare local part ("To: d"): as Dovecot's ENVELOPE, it gets the MISSING_DOMAIN host, so it
		// stays an address (a NIL host would read as a group start) and SORT keys on it.
		// Anything else that is no dot-atom is dropped, as before.
		tok, rest, _ := strings.Cut(s, ",")
		if tok = strings.TrimSpace(tok); isDotAtom(tok) {
			out = append(out, &mail.Address{Address: tok + "@" + missingDomain})
		}
		s = rest
	}
	return out
}

// isDotAtom reports whether s is an RFC 5322 3.2.3 dot-atom-text.
func isDotAtom(s string) bool {
	if s == "" || s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' ||
			strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0) {
			return false
		}
	}
	return true
}

// missingDomain is the host of an address that has none (Dovecot's placeholder).
const missingDomain = "MISSING_DOMAIN"

// firstAddrMailbox is the RFC 5256 FROM/TO/CC sort value: the addr-mailbox of the first ENVELOPE
// address (a group name for a group).
func firstAddrMailbox(value string) string {
	if addrs := ParseAddressField(value); len(addrs) > 0 {
		return addrs[0].Mailbox
	}
	return ""
}

// firstAddrDisplay is the RFC 5957 3 sort value of the first ENVELOPE address: its decoded
// display name, else mailbox@host, else the mailbox alone (a group name).
func firstAddrDisplay(value string) string {
	addrs := ParseAddressField(value)
	if len(addrs) == 0 {
		return ""
	}
	a := addrs[0]
	switch {
	case a.Name != "":
		return a.Name
	case a.Mailbox != "" && a.Host != "":
		return a.Mailbox + "@" + a.Host
	}
	return a.Mailbox
}
