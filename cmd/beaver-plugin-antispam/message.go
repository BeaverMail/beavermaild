// Message model: raw headers, MIME parts, text and HTML content, URLs.
package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

const (
	maxParts     = 256
	maxDepth     = 8
	maxURLs      = 512
	maxPartBytes = 8 << 20
)

type header struct {
	name     string
	raw      string // unfolded value, leading blanks trimmed
	emptySep bool   // "Name:value" with no blank after the colon
}

type anchor struct{ href, text string }

type image struct {
	w, h               int
	inAnchor, embedded bool
}

type htmlInfo struct {
	anchors []anchor
	images  []image
	links   []string // <link href>
}

type part struct {
	ctype      string // lowercase type/subtype
	params     map[string]string
	hdr        textproto.MIMEHeader
	parent     *part
	body       []byte // decoded content (leaf parts)
	filename   string
	attachment bool
	broken     bool
	isText     bool // text/plain or text/html content part
	text       string
	lines      int
	html       *htmlInfo
}

type msgURL struct {
	raw  string
	u    *url.URL
	host string // lowercase, no port
	html bool
}

type message struct {
	headers []header
	parts   []*part
	urls    []*msgURL
	raw     []byte
}

var wordDec = mime.WordDecoder{CharsetReader: func(_ string, r io.Reader) (io.Reader, error) { return r, nil }}

func decodeWords(s string) string {
	if d, err := wordDec.DecodeHeader(s); err == nil {
		return d
	}
	return s
}

func parseMessage(raw []byte) *message {
	m := &message{raw: raw}
	hdrEnd, bodyStart := len(raw), len(raw)
	for _, sep := range []string{"\r\n\r\n", "\n\n"} {
		if i := bytes.Index(raw, []byte(sep)); i >= 0 && i < hdrEnd {
			hdrEnd, bodyStart = i, i+len(sep)
		}
	}
	m.headers = parseHeaderBlock(string(raw[:hdrEnd]))
	top := textproto.MIMEHeader{}
	for _, h := range m.headers {
		top.Add(textproto.CanonicalMIMEHeaderKey(h.name), h.raw)
	}
	m.parsePart(top, raw[bodyStart:], nil, 0)
	m.collectURLs()
	return m
}

func parseHeaderBlock(block string) []header {
	var out []header
	for _, line := range strings.Split(strings.ReplaceAll(block, "\r\n", "\n"), "\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(out) == 0 {
				continue
			}
			out[len(out)-1].raw += " " + strings.TrimSpace(line)
			continue
		}
		name, val, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			continue
		}
		out = append(out, header{name: name, raw: strings.TrimSpace(val), emptySep: val != "" && val[0] != ' ' && val[0] != '\t'})
	}
	return out
}

// get returns the first raw value of name (case-insensitive).
func (m *message) get(name string) (string, bool) {
	for _, h := range m.headers {
		if strings.EqualFold(h.name, name) {
			return h.raw, true
		}
	}
	return "", false
}

func (m *message) all(name string) []header {
	var out []header
	for _, h := range m.headers {
		if strings.EqualFold(h.name, name) {
			out = append(out, h)
		}
	}
	return out
}

func (m *message) has(name string) bool { _, ok := m.get(name); return ok }

func (m *message) decoded(name string) (string, bool) {
	v, ok := m.get(name)
	return decodeWords(v), ok
}

// hasExactCase reports a header spelled exactly as name (rspamd's case-sensitive has_header).
func (m *message) hasExactCase(name string) bool {
	for _, h := range m.headers {
		if h.name == name {
			return true
		}
	}
	return false
}

// addrs parses an address header; ok is false when the header is present but unparseable.
func (m *message) addrs(name string) (list []*mail.Address, present, ok bool) {
	v, present := m.get(name)
	if !present {
		return nil, false, true
	}
	list, err := (&mail.AddressParser{WordDecoder: &wordDec}).ParseList(v)
	return list, true, err == nil && len(list) > 0
}

func (m *message) parsePart(h textproto.MIMEHeader, body []byte, parent *part, depth int) {
	if len(m.parts) >= maxParts {
		return
	}
	p := &part{hdr: h, parent: parent, ctype: "text/plain", params: map[string]string{}}
	m.parts = append(m.parts, p)
	if ct := h.Get("Content-Type"); ct != "" {
		mt, params, err := mime.ParseMediaType(ct)
		if err != nil || !strings.Contains(mt, "/") {
			p.broken = true
			mt = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
		}
		if strings.Contains(mt, "/") {
			p.ctype = mt
		}
		if params != nil {
			p.params = params
		}
	}
	disp, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	p.filename = decodeWords(dparams["filename"])
	if p.filename == "" {
		p.filename = decodeWords(p.params["name"])
	}
	p.attachment = disp == "attachment" || (p.filename != "" && disp != "inline")

	if strings.HasPrefix(p.ctype, "multipart/") {
		if depth >= maxDepth || p.params["boundary"] == "" {
			p.broken = true
			return
		}
		mr := multipart.NewReader(bytes.NewReader(body), p.params["boundary"])
		for {
			cp, err := mr.NextRawPart()
			if err != nil {
				if err != io.EOF {
					p.broken = true
				}
				return
			}
			b, _ := io.ReadAll(io.LimitReader(cp, maxPartBytes))
			m.parsePart(cp.Header, b, p, depth+1)
		}
	}
	p.body = decodeCTE(h.Get("Content-Transfer-Encoding"), body)
	if p.attachment || (p.ctype != "text/plain" && p.ctype != "text/html") {
		return
	}
	p.isText = true
	if p.ctype == "text/html" {
		p.html, p.text = parseHTML(p.body)
	} else {
		p.text = string(p.body)
	}
	p.lines = strings.Count(strings.TrimSpace(p.text), "\n") + 1
}

func decodeCTE(cte string, body []byte) []byte {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		clean := bytes.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, body)
		out := make([]byte, base64.StdEncoding.DecodedLen(len(clean)))
		n, _ := base64.StdEncoding.Decode(out, clean)
		return out[:n]
	case "quoted-printable":
		out, _ := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		return out
	}
	return body
}

var blockTags = map[string]bool{"br": true, "p": true, "div": true, "tr": true, "li": true, "h1": true, "h2": true, "h3": true, "table": true}

// parseHTML extracts visible text, anchors, images and <link> targets.
func parseHTML(b []byte) (*htmlInfo, string) {
	info := &htmlInfo{}
	var text strings.Builder
	z := html.NewTokenizer(bytes.NewReader(b))
	skip, inA := 0, 0
	var cur *anchor
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if cur != nil {
				info.anchors = append(info.anchors, *cur)
			}
			return info, text.String()
		case html.TextToken:
			if skip == 0 {
				t := html.UnescapeString(string(z.Text()))
				text.WriteString(t)
				if cur != nil {
					cur.text += t
				}
			}
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			attrs := map[string]string{}
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				attrs[string(k)] = string(v)
			}
			end := tt == html.EndTagToken
			switch {
			case tag == "script" || tag == "style" || tag == "head":
				if end && skip > 0 {
					skip--
				} else if tt == html.StartTagToken {
					skip++
				}
			case tag == "a" && !end:
				if cur != nil {
					info.anchors = append(info.anchors, *cur)
				}
				cur = &anchor{href: strings.TrimSpace(attrs["href"])}
				inA++
			case tag == "a" && end:
				if cur != nil {
					info.anchors = append(info.anchors, *cur)
					cur = nil
				}
				if inA > 0 {
					inA--
				}
			case tag == "img" && !end:
				w, _ := strconv.Atoi(strings.TrimSuffix(attrs["width"], "px"))
				h, _ := strconv.Atoi(strings.TrimSuffix(attrs["height"], "px"))
				src := strings.ToLower(attrs["src"])
				info.images = append(info.images, image{w: w, h: h, inAnchor: inA > 0,
					embedded: strings.HasPrefix(src, "cid:") || strings.HasPrefix(src, "data:")})
			case tag == "link" && !end:
				info.links = append(info.links, attrs["href"])
			}
			if blockTags[tag] && skip == 0 {
				text.WriteByte('\n')
			}
		}
	}
}

var textURLRe = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"'(){}\[\]]+`)

func newURL(raw string, fromHTML bool) *msgURL {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil
	}
	return &msgURL{raw: raw, u: u, host: strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), html: fromHTML}
}

func (m *message) addURL(raw string, fromHTML bool) {
	if len(m.urls) >= maxURLs {
		return
	}
	for _, x := range m.urls {
		if x.raw == raw {
			return
		}
	}
	if u := newURL(raw, fromHTML); u != nil {
		m.urls = append(m.urls, u)
	}
}

func (m *message) collectURLs() {
	for _, p := range m.textParts() {
		for _, s := range textURLRe.FindAllString(p.text, -1) {
			m.addURL(strings.TrimRight(s, ".,;:!?"), p.html != nil)
		}
		if p.html != nil {
			for _, a := range p.html.anchors {
				m.addURL(a.href, true)
			}
		}
	}
}

func (m *message) textParts() []*part {
	var out []*part
	for _, p := range m.parts {
		if p.isText {
			out = append(out, p)
		}
	}
	return out
}

// textURLLen sums the length of URLs written in the part's visible text (hfilter url checks).
func textURLLen(p *part) int {
	n := 0
	for _, s := range textURLRe.FindAllString(p.text, -1) {
		n += len(s)
	}
	return n
}
