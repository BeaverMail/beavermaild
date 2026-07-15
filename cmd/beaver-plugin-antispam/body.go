// MIME body parse and harvest (Phase 3-4).
package main

import (
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"strings"
)

type messageBody struct {
	parts       []mimePart
	mimeVersion string
	empty       bool
}

type mimePart struct {
	contentType string
	charset     string
	disposition string
	filename    string
	body        []byte
	isHTML      bool
	isPlain     bool
}

const maxBodyRead = 2 << 20 // 2 MiB cap per classify

func loadMessageBody(path string) (*messageBody, *harvestSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	lim := io.LimitReader(f, maxBodyRead)
	msg, err := mail.ReadMessage(lim)
	if err != nil {
		return nil, nil, err
	}
	mb := &messageBody{mimeVersion: msg.Header.Get("Mime-Version")}
	h := newHarvestSet()
	ct := msg.Header.Get("Content-Type")
	if ct == "" {
		b, _ := io.ReadAll(msg.Body)
		mb.parts = append(mb.parts, mimePart{contentType: "text/plain", body: b, isPlain: true})
		h.plain = string(b)
		h.hasPlain = len(b) > 0
		harvestFromText(h, h.plain)
		if len(b) == 0 {
			mb.empty = true
		}
		return mb, h, nil
	}
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		b, _ := io.ReadAll(msg.Body)
		harvestFromText(h, string(b))
		return mb, h, nil
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return mb, h, nil
		}
		mr := multipart.NewReader(msg.Body, boundary)
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			pct := p.Header.Get("Content-Type")
			pt, partParams, _ := mime.ParseMediaType(pct)
			if pt == "" {
				pt = pct
			}
			b, _ := io.ReadAll(io.LimitReader(p, 512*1024))
			part := mimePart{
				contentType: pt,
				charset:     strings.ToLower(partParams["charset"]),
				disposition: p.Header.Get("Content-Disposition"),
				filename:    filenameFromDisposition(p.Header.Get("Content-Disposition")),
				body:        b,
				isHTML:      strings.HasPrefix(strings.ToLower(pt), "text/html"),
				isPlain:     strings.HasPrefix(strings.ToLower(pt), "text/plain"),
			}
			mb.parts = append(mb.parts, part)
			if part.isPlain {
				h.plain += string(b) + "\n"
				h.hasPlain = true
				harvestFromText(h, string(b))
			}
			if part.isHTML {
				h.html += string(b) + "\n"
				h.hasHTML = true
				harvestFromText(h, htmlToText(string(b)))
				harvestFromText(h, string(b))
			}
		}
		if !h.hasPlain && !h.hasHTML && len(mb.parts) == 0 {
			mb.empty = true
		}
		return mb, h, nil
	}
	b, _ := io.ReadAll(msg.Body)
	isHTML := strings.HasPrefix(strings.ToLower(mediaType), "text/html")
	isPlain := strings.HasPrefix(strings.ToLower(mediaType), "text/plain")
	mb.parts = append(mb.parts, mimePart{
		contentType: mediaType,
		charset:     strings.ToLower(params["charset"]),
		body:        b,
		isHTML:      isHTML,
		isPlain:     isPlain,
	})
	if isPlain {
		h.plain = string(b)
		h.hasPlain = true
		harvestFromText(h, h.plain)
	}
	if isHTML {
		h.html = string(b)
		h.hasHTML = true
		harvestFromText(h, htmlToText(h.html))
	}
	if len(b) == 0 {
		mb.empty = true
	}
	return mb, h, nil
}

func filenameFromDisposition(d string) string {
	_, params, err := mime.ParseMediaType(d)
	if err != nil {
		return ""
	}
	return params["filename"]
}
