// Message model: raw headers, MIME parts, text and HTML content, URLs.
package main

import (
	"bytes"
	"io"
	"mime"
	"net/mail"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/BeaverMail/beavermaild/mimetree"
	htmlcharset "golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"

	"golang.org/x/net/html"
)

const (
	maxURLs      = 512
	maxPartBytes = 8 << 20 // decoded and analysed per leaf part; the rest of a larger part is not read
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
	opaque     bool // not entered: past the MIME depth or part limit (mimetree)
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

// wordDec decodes RFC 2047 encoded-words in any charset x/text knows; others stay as raw bytes.
var wordDec = mime.WordDecoder{CharsetReader: func(cs string, r io.Reader) (io.Reader, error) {
	if e, err := htmlindex.Get(cs); err == nil && e != encoding.Replacement {
		return e.NewDecoder().Reader(r), nil
	}
	return r, nil
}}

// toUTF8 converts text in charset to UTF-8, as the client shows it (RFC 2049 2). An unknown charset
// keeps the raw bytes: the ASCII in them, URLs included, is still read.
func toUTF8(b []byte, charset string) []byte {
	switch strings.ToLower(charset) {
	case "", "utf-8", "us-ascii":
		return b
	}
	e, err := htmlindex.Get(charset)
	if err != nil {
		return b
	}
	return decodeWith(b, e)
}

// htmlToUTF8 converts an HTML part as a browser engine does (x/net/html/charset): byte order mark,
// then the Content-Type charset, then a <meta> charset in the first 1024 bytes, then UTF-8 if the
// bytes are. Ignoring <meta> let a part declare a charset there whose escape sequences, inside a
// link, kept the filter from reading a URL the client shows.
func htmlToUTF8(b []byte, contentType string) []byte {
	e, _, _ := htmlcharset.DetermineEncoding(b, contentType)
	return decodeWith(b, e)
}

// decodeWith decodes b with e. WHATWG maps some charsets (iso-2022-kr, hz-gb-2312...) to
// "replacement", one U+FFFD for the whole text: the content would vanish for the filter while a
// client that knows them shows it, so their bytes are kept.
func decodeWith(b []byte, e encoding.Encoding) []byte {
	if e == nil || e == encoding.Replacement {
		return b
	}
	out, err := e.NewDecoder().Bytes(b)
	if err != nil {
		return b
	}
	return out
}

func decodeWords(s string) string {
	if d, err := wordDec.DecodeHeader(s); err == nil {
		return d
	}
	return s
}

func parseMessage(raw []byte) *message {
	m := &message{raw: raw}
	tree := mimetree.Parse(raw)
	m.headers = parseHeaderBlock(string(tree.Header))
	m.addPart(tree, nil)
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

// addPart adds t and its subtree. The tree is the one IMAP shows clients (package mimetree): what
// a client can display, the filter reads, message/rfc822 parts included.
func (m *message) addPart(t *mimetree.Part, parent *part) {
	p := &part{hdr: t.MIME, parent: parent, ctype: t.Type, params: t.Params}
	if p.params == nil {
		p.params = map[string]string{}
	}
	m.parts = append(m.parts, p)
	// Repeated Content-Type or Content-Transfer-Encoding, a malformed header line, an encoded
	// multipart: each client reads them its own way, the filter cannot know which.
	p.broken = t.BadType || t.BadHeader || t.BadEncoding || len(t.MIME["Content-Type"]) > 1 || len(t.MIME["Content-Transfer-Encoding"]) > 1 ||
		t.IsMultipart() && t.Params["boundary"] == ""
	p.opaque = t.Opaque || t.Truncated
	disp, dparams, _ := mime.ParseMediaType(t.MIME.Get("Content-Disposition"))
	p.filename = decodeWords(dparams["filename"])
	if p.filename == "" {
		p.filename = decodeWords(p.params["name"])
	}
	p.attachment = disp == "attachment" || (p.filename != "" && disp != "inline")

	if len(t.Children) > 0 || t.IsMultipart() {
		for _, c := range t.Children {
			m.addPart(c, p)
		}
		return
	}
	body := t.Body
	if len(body) > maxPartBytes {
		body = body[:maxPartBytes]
	}
	p.body, _ = mimetree.Decode(t.MIME.Get("Content-Transfer-Encoding"), body)
	if p.attachment || (p.ctype != "text/plain" && p.ctype != "text/html") {
		return
	}
	p.isText = true
	if p.ctype == "text/html" {
		p.html, p.text = parseHTML(htmlToUTF8(p.body, t.MIME.Get("Content-Type")))
	} else {
		p.text = string(toUTF8(p.body, p.params["charset"]))
	}
	p.lines = strings.Count(strings.TrimSpace(p.text), "\n") + 1
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
