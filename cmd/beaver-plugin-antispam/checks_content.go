// Derived from rspamd (https://github.com/rspamd/rspamd), Copyright (c) Vsevolod Stakhov and the
// rspamd contributors, Apache License 2.0 (LICENSES/Apache-2.0.txt): src/libmime/message.c, rules/{headers_checks,html}.lua,
// src/plugins/lua/{mime_types,url_suspect,phishing}.lua and conf/maps.d/suspicious_tlds.inc.
// Includes regular expressions from Apache SpamAssassin, Copyright The Apache Software Foundation.
// Translated to Go and modified for BeaverMail; see NOTICE.

// Content checks: GTUBE, MIME structure, attachment names, HTML, URLs and phishing.
package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// GTUBE patterns and their forced actions (rspamd src/libmime/message.c).
const gtubeSuffix = "JS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"

func checkGTUBE(policy string, m *message, r *result) {
	if policy == "disabled" {
		return
	}
	acts := map[byte]string{'X': actReject}
	if policy == "all" {
		acts['Y'], acts['Z'], acts['A'] = actAddHeader, actRewrite, actNone
	}
	for _, p := range m.textParts() {
		i := strings.Index(p.text, gtubeSuffix)
		if i < 1 {
			continue
		}
		if act, ok := acts[p.text[i-1]]; ok {
			r.add("GTUBE", 1)
			r.forced = act
			return
		}
	}
}

// checkMIMEParts ports the MIME structure rules of headers_checks.lua and regexp/headers.lua.
func checkMIMEParts(m *message, r *result) {
	root := m.parts[0]
	if (m.has("Content-Type") || m.has("Content-Transfer-Encoding")) && !m.has("MIME-Version") {
		r.add("MISSING_MIME_VERSION", 1)
	}
	if !m.has("Content-Disposition") && !m.has("Content-Transfer-Encoding") && m.has("Content-Type") &&
		!m.has("MIME-Version") && root.ctype != "text/plain" {
		r.add("MIME_HEADER_CTYPE_ONLY", 1)
	}
	if cte, ok := m.get("Content-Transfer-Encoding"); ok && root.ctype == "text/plain" && root.params["charset"] == "" &&
		!strings.EqualFold(strings.TrimSpace(cte), "7bit") && len(bytes.TrimSpace(root.body)) > 0 {
		r.add("R_MISSING_CHARSET", 1)
	}
	var ma, plain, htm bool
	textNonAtt, nonText := 0, false
	for _, p := range m.parts {
		switch p.ctype {
		case "multipart/alternative":
			ma = true
		case "text/plain":
			plain = true
		case "text/html":
			htm = true
		}
		if p.broken {
			r.add("BROKEN_CONTENT_TYPE", 1)
		}
		mt, _, _ := strings.Cut(p.ctype, "/")
		if mt == "text" && !p.attachment {
			textNonAtt++
		} else if mt != "multipart" {
			nonText = true
		}
		if strings.HasPrefix(strings.ToLower(p.hdr.Get("Content-Type")), "text") &&
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(p.hdr.Get("Content-Transfer-Encoding"))), "base64") {
			r.add("MIME_BASE64_TEXT", 1)
			if p.isText && !has8bit(string(p.body)) {
				r.add("MIME_BASE64_TEXT_BOGUS", 1)
			}
		}
		if strings.HasPrefix(strings.ToLower(p.hdr.Get("Content-Type")), "application/octet-stream") {
			cd := strings.ToLower(p.hdr.Get("Content-Disposition"))
			encrypted := p.parent != nil && p.parent.ctype == "multipart/encrypted"
			asc := len(m.parts) > 1 && ascRe.MatchString(cd)
			if !strings.HasPrefix(cd, "attachment") && p.hdr.Get("Content-ID") == "" && !asc && !encrypted {
				r.add("CTYPE_MISSING_DISPOSITION", 1)
			}
		}
		if p.isText && trackerID.MatchString(p.text) {
			r.add("TRACKER_ID", 1)
		}
	}
	if ma && !plain {
		r.add("MIME_MA_MISSING_TEXT", 1)
	}
	if ma && !htm {
		r.add("MIME_MA_MISSING_HTML", 1)
	}
	if root.ctype == "multipart/mixed" && !nonText && textNonAtt <= 2 {
		r.add("CTYPE_MIXED_BOGUS", 1)
	}
}

// Tables from rspamd src/plugins/lua/mime_types.lua (badness multipliers).
var (
	badExtensions = map[string]float64{"cue": 2, "exe": 1, "iso": 4, "jar": 2, "txz": 2, "zpaq": 2, "htm": 1,
		"html": 1, "shtm": 1, "shtml": 1, "ace": 4, "arj": 2, "aspx": 1, "asx": 2, "cab": 3, "dll": 4, "dqy": 2,
		"iqy": 2, "mht": 2, "mhtml": 2, "oqy": 2, "rdp": 2, "rqy": 2, "sfx": 2, "slk": 2, "vst": 2, "vss": 2,
		"wim": 2, "ade": 4, "adp": 4, "cmd": 4, "cpl": 4, "ins": 4, "isp": 4, "js": 4, "jse": 4, "lib": 4,
		"mde": 4, "msc": 4, "msi": 4, "msp": 4, "mst": 4, "nsh": 4, "pif": 4, "sct": 4, "shb": 4, "sys": 4,
		"vb": 4, "vbe": 4, "vbs": 4, "vxd": 4, "wsc": 4, "wsh": 4, "app": 4, "asp": 4, "bas": 4, "bat": 4,
		"chm": 4, "cnt": 4, "com": 4, "csh": 4, "diagcab": 4, "fxp": 4, "gadget": 4, "grp": 4, "hlp": 4,
		"hpj": 4, "hta": 4, "htc": 4, "inf": 4, "its": 4, "jnlp": 4, "library-ms": 4, "lnk": 4, "ksh": 4,
		"mad": 4, "maf": 4, "mag": 4, "mam": 4, "maq": 4, "mar": 4, "mas": 4, "mat": 4, "mau": 4, "mav": 4,
		"maw": 4, "mcf": 4, "mda": 4, "mdb": 4, "mdt": 4, "mdw": 4, "mdz": 4, "msh": 4, "msh1": 4, "msh2": 4,
		"mshxml": 4, "msh1xml": 4, "msh2xml": 4, "msu": 4, "ops": 4, "osd": 4, "pcd": 4, "pl": 4, "plg": 4,
		"prf": 4, "prg": 4, "printerexport": 4, "ps1": 4, "ps1xml": 4, "ps2": 4, "ps2xml": 4, "psc1": 4,
		"psc2": 4, "psd1": 4, "psdm1": 4, "pst": 4, "pyc": 4, "pyo": 4, "pyw": 4, "pyz": 4, "pyzw": 4, "reg": 4,
		"scf": 4, "scr": 4, "search-ms": 4, "shs": 4, "theme": 4, "url": 4, "vbp": 4, "vhd": 4, "vhdx": 4,
		"vsmacros": 4, "vsw": 4, "webpnp": 4, "website": 4, "ws": 4, "wsf": 4, "xbap": 4, "xll": 4, "xnk": 4}
	badArchiveExtensions = map[string]float64{"chm": 4, "docx": 0.1, "exe": 0.1, "hta": 4, "iso": 4, "jar": 3,
		"js": 0.5, "lnk": 4, "pdf": 0.1, "pptx": 0.1, "vbs": 4, "wsf": 4, "xlsx": 0.1}
	archiveExtensions = map[string]bool{"7z": true, "ace": true, "alz": true, "arj": true, "bz2": true, "cab": true,
		"egg": true, "lz": true, "rar": true, "txz": true, "xz": true, "zip": true, "zpaq": true}
	extensionMap = map[string]string{"html": "text/html", "htm": "text/html", "pdf": "application/pdf",
		"shtm": "text/html", "shtml": "text/html", "txt": "text/plain"}
	ascRe        = regexp.MustCompile(`filename=.+\.asc`)
	numericExtRe = regexp.MustCompile(`^\d+[\])]?$`)
	pctHexRe     = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
)

// obscuredUnicode reports bidi controls and zero-width characters (rspamd has_obscured_unicode).
func obscuredUnicode(s string) bool {
	for _, c := range s {
		if (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || (c >= 0x200b && c <= 0x200f) || c == 0xfeff || c == 0x00ad {
			return true
		}
	}
	return false
}

// checkFilename ports check_filename of mime_types.lua (without content-type magic detection).
func checkFilename(fname, ct string, isArchive bool, nfiles int, r *result) {
	if obscuredUnicode(fname) {
		r.add("MIME_BAD_UNICODE", 1, fname)
	}
	fname = pctHexRe.ReplaceAllStringFunc(fname, func(h string) string {
		b, _ := strconv.ParseUint(h[1:], 16, 8)
		return string(rune(b))
	})
	parts := strings.Split(fname, ".")
	if len(parts) < 2 {
		return
	}
	ext := strings.ToLower(parts[len(parts)-1])
	ext2 := ""
	if len(parts) > 2 {
		ext2 = strings.ToLower(parts[len(parts)-2])
	}
	lookup := func(e string) float64 {
		if isArchive && nfiles < 2 && badArchiveExtensions[e] > 0 {
			return badArchiveExtensions[e]
		}
		return badExtensions[e]
	}
	b1, b2 := lookup(ext), 0.0
	if ext2 != "" {
		b2 = lookup(ext2)
	}
	if b1 > 0 || b2 > 0 {
		if ext2 != "" && len(ext2) <= 4 && !numericExtRe.MatchString(ext2) {
			r.add("MIME_DOUBLE_BAD_EXTENSION", max(b1, b2), "."+ext2+"."+ext)
		} else if b1 > 0 {
			r.add("MIME_BAD_EXTENSION", b1, ext)
		}
	}
	switch {
	case isArchive && archiveExtensions[ext]:
		r.add("MIME_ARCHIVE_IN_ARCHIVE", 1, ext)
	case !isArchive && archiveExtensions[ext2] && !numericExtRe.MatchString(ext):
		r.add("MIME_ARCHIVE_IN_ARCHIVE", 1, "."+ext2+"."+ext)
	}
	if want, ok := extensionMap[ext]; ok && ct != "" && ct != "application/octet-stream" && ct != want {
		r.add("MIME_BAD_ATTACHMENT", 1, ext+":"+ct)
	}
}

// checkMIMETypes checks attachment names, and the file names inside ZIP attachments.
func checkMIMETypes(m *message, r *result) {
	for _, p := range m.parts {
		if p.filename == "" {
			continue
		}
		checkFilename(p.filename, p.ctype, false, 1, r)
		if !strings.HasSuffix(strings.ToLower(p.filename), ".zip") && p.ctype != "application/zip" {
			continue
		}
		zr, err := zip.NewReader(bytes.NewReader(p.body), int64(len(p.body)))
		if err != nil {
			continue
		}
		for i, f := range zr.File {
			if i >= 1000 {
				break
			}
			if f.Flags&1 != 0 {
				r.add("MIME_ENCRYPTED_ARCHIVE", 1, p.filename)
			}
			checkFilename(f.Name, "", true, len(zr.File), r)
		}
	}
}

var cssRe = regexp.MustCompile(`(?i)^.*\.css(?:[?#].*)?$`)
var httpIPRe = regexp.MustCompile(`^https?://\d+\.\d+\.\d+\.\d+`)

func textLen(s string) int { return len(strings.Join(strings.Fields(s), " ")) }

// checkHTML ports rules/html.lua (except the CSS visibility rules).
func checkHTML(m *message, r *result) {
	plain, htmlParts := 0, 0
	for _, p := range m.textParts() {
		if p.html == nil {
			plain++
			continue
		}
		htmlParts++
		n := textLen(p.text)
		for _, img := range p.html.images {
			if img.inAnchor && img.embedded && img.w+img.h >= 210 {
				switch {
				case n < 1024:
					r.add("HTML_SHORT_LINK_IMG_1", 1)
				case n < 1536:
					r.add("HTML_SHORT_LINK_IMG_2", 1)
				case n < 2048:
					r.add("HTML_SHORT_LINK_IMG_3", 1)
				}
			}
			if n < 50 && !img.inAnchor && img.w+img.h >= 400 {
				r.add("R_EMPTY_IMAGE", 1)
			}
		}
		for _, l := range p.html.links {
			if cssRe.MatchString(l) {
				r.add("EXT_CSS", 1)
			}
		}
		for _, a := range p.html.anchors {
			href := strings.ToLower(a.href)
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.text)), "https:") && strings.HasPrefix(href, "http:") {
				if u := newURL(a.href, true); u != nil {
					r.add("HTTP_TO_HTTPS", 1, u.host)
				}
			}
			if httpIPRe.MatchString(href) {
				r.add("HTTP_TO_IP", 1)
			}
		}
	}
	if htmlParts > 0 && plain == 0 {
		r.add("MIME_HTML_ONLY", 1)
	}
}

// suspiciousTLDs is rspamd conf/maps.d/suspicious_tlds.inc.
var suspiciousTLDs = map[string]bool{"tk": true, "ml": true, "ga": true, "cf": true, "gq": true}

// checkURLs ports url_suspect.lua (user/password, numeric IP, TLD, unicode and structure checks).
func checkURLs(m *message, r *result) {
	for _, u := range m.urls {
		host := u.host
		if ui := u.u.User; ui != nil {
			switch n := len(ui.String()); {
			case n > 256:
				r.add("URL_USER_VERY_LONG", 1, strconv.Itoa(n))
			case n > 128:
				r.add("URL_USER_LONG", 1, strconv.Itoa(n))
			default:
				r.add("URL_USER_PASSWORD", 1, host)
			}
		}
		if ip := net.ParseIP(host); ip != nil {
			switch {
			case isLocalIP(ip):
				r.add("URL_NUMERIC_PRIVATE_IP", 1, host)
			case u.u.User != nil:
				r.add("URL_NUMERIC_IP_USER", 1, host)
			default:
				r.add("URL_NUMERIC_IP", 1, host)
			}
		} else if ps, icann := publicsuffix.PublicSuffix(host); !icann && !strings.Contains(ps, ".") {
			r.add("URL_NO_TLD", 1, host)
		} else if suspiciousTLDs[ps] {
			r.add("URL_SUSPICIOUS_TLD", 1, ps)
		}
		for _, c := range u.raw {
			if c == 0x202e || c == 0x202d || (c >= 0x2066 && c <= 0x2069) {
				r.add("URL_RTL_OVERRIDE", 1, host)
				break
			}
		}
		if strings.ContainsAny(host, "\u200b\u200c\u200d\ufeff\u00ad") {
			r.add("URL_ZERO_WIDTH_SPACES", 1, host)
		}
		if n := strings.Count(host, "."); n > 6 {
			r.add("URL_EXCESSIVE_DOTS", 1, strconv.Itoa(n))
		}
		if strings.Contains(u.raw, `\`) {
			r.add("URL_BACKSLASH_PATH", 1, host)
		}
		if len(u.raw) > 2048 {
			r.add("URL_VERY_LONG", 1, strconv.Itoa(len(u.raw)))
		}
		if n := strings.Count(u.raw, "@"); n > 2 {
			r.add("URL_MULTIPLE_AT_SIGNS", 1, strconv.Itoa(n))
		}
		q, err := url.QueryUnescape(u.u.RawQuery)
		if err != nil {
			q = u.u.RawQuery
		}
		if n := strings.Count(strings.ToLower(q), "http://") + strings.Count(strings.ToLower(q), "https://"); n > 1 {
			r.add("URL_QUERY_MULTIPLE_URLS", 1, strconv.Itoa(n))
		}
	}
}

var wwwRe = regexp.MustCompile(`(?i)^www\.[^\s/]+\.[a-z]{2,}`)

// displayedURL parses anchor text that looks like a URL (rspamd's "phished" displayed URL).
func displayedURL(text string) *msgURL {
	t := strings.TrimSpace(text)
	if wwwRe.MatchString(t) {
		t = "http://" + t
	}
	if !strings.HasPrefix(strings.ToLower(t), "http://") && !strings.HasPrefix(strings.ToLower(t), "https://") {
		return nil
	}
	if f := strings.Fields(t); len(f) > 0 {
		t = f[0]
	}
	return newURL(t, true)
}

// levenshtein with substitution cost 2 (rspamd util.levenshtein_distance(a, b, 2)).
func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			sub := prev[j-1]
			if a[i-1] != b[j-1] {
				sub += 2
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, sub)
		}
		prev = cur
	}
	return prev[len(b)]
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// phishWeight is phishing.lua's weight for a displayed eSLD ptld shown over a link to tld.
func phishWeight(tld, ptld string, plain bool) float64 {
	st, sp := tld, ptld
	if plain {
		if l, _, ok := strings.Cut(tld, "."); ok {
			if pl, _, ok := strings.Cut(ptld, "."); ok {
				st, sp = l, pl
			}
		}
	}
	if st == sp {
		return 0
	}
	dist := 2 * float64(levenshtein(st, sp)) / float64(len(st)+len(sp))
	switch {
	case dist > 0.3 && dist <= 1:
		return math.Tanh(3 * (1 - dist + 0.1))
	case dist > 1:
		if isASCII(tld) != isASCII(ptld) {
			return 1
		}
		return 0.5
	}
	return 1
}

// checkPhishing ports the displayed-vs-target comparison of phishing.lua (no external feeds).
func checkPhishing(m *message, a *authResults, r *result) {
	dmarcDom := ""
	if a != nil && a.DMARC == "pass" {
		dmarcDom = esld(fromDomain(m))
	}
	for _, p := range m.textParts() {
		if p.html == nil {
			continue
		}
		for _, an := range p.html.anchors {
			href, disp := newURL(an.href, true), displayedURL(an.text)
			if href == nil || disp == nil {
				continue
			}
			tld, ptld := esld(href.host), esld(disp.host)
			if tld == ptld {
				continue
			}
			r.add("URL_DISPLAY_MISMATCH", 1, ptld+"->"+tld)
			if dmarcDom != "" && tld == dmarcDom {
				continue
			}
			numeric := net.ParseIP(href.host) != nil || net.ParseIP(disp.host) != nil
			if w := phishWeight(tld, ptld, !numeric); w > 0 {
				r.add("PHISHING", w, fmt.Sprintf("%s->%s", ptld, tld))
			}
		}
	}
}
