// IMAP URLs (RFC 5092) naming a message or part, as CATENATE (RFC 4469) and URLAUTH (RFC 4467) use.
package imap

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// imapURL is a parsed message URL: "[imap://[user[;AUTH=x]@]host[:port]]/mailbox[;UIDVALIDITY=n]
// /;UID=n[/;SECTION=s][/;PARTIAL=o[.l]][;EXPIRE=t][;URLAUTH=access:mech:token]".
type imapURL struct {
	absolute    bool
	user, host  string
	mailbox     string // IMAP wire name (modified UTF-7)
	uidValidity uint32
	uid         uint32
	section     string
	partial     bool
	origin      int
	length      int // -1: to the end
	expire      string
	access      string // URLAUTH access identifier ("user+name", "authuser", ...)
	mech, token string // URLAUTH mechanism and token, empty in a URL to authorize
}

// parseIMAPURL parses a URL naming one message (UID required).
func parseIMAPURL(raw string) (imapURL, bool) {
	u := imapURL{length: -1}
	rest := raw
	if len(rest) >= 7 && strings.EqualFold(rest[:7], "imap://") {
		u.absolute = true
		auth, path, found := strings.Cut(rest[7:], "/")
		if !found {
			return u, false
		}
		if at := strings.LastIndexByte(auth, '@'); at >= 0 {
			userinfo, host := auth[:at], auth[at+1:]
			user, _, _ := strings.Cut(userinfo, ";")
			var err error
			if u.user, err = url.PathUnescape(user); err != nil || u.user == "" {
				return u, false
			}
			auth = host
		}
		u.host = strings.ToLower(auth)
		rest = "/" + path
	}
	if !strings.HasPrefix(rest, "/") {
		return u, false
	}
	rest = rest[1:]
	// The mailbox may hold "/" itself: it ends at ";UIDVALIDITY=" or "/;UID=".
	upper := strings.ToUpper(rest)
	end := strings.Index(upper, "/;UID=")
	if i := strings.Index(upper, ";UIDVALIDITY="); i >= 0 && (end < 0 || i < end) {
		end = i
	}
	if end <= 0 {
		return u, false
	}
	name, err := url.PathUnescape(rest[:end])
	if err != nil {
		return u, false
	}
	u.mailbox = encodeMUTF7(name)
	for _, p := range strings.Split(strings.ReplaceAll(rest[end:], "/;", ";"), ";")[1:] {
		key, val, ok := strings.Cut(p, "=")
		if !ok {
			return u, false
		}
		switch strings.ToUpper(key) {
		case "UIDVALIDITY":
			n, ok := parseNZNumber(val)
			if !ok || u.uid != 0 {
				return u, false
			}
			u.uidValidity = uint32(n)
		case "UID":
			n, ok := parseNZNumber(val)
			if !ok || u.uid != 0 {
				return u, false
			}
			u.uid = uint32(n)
		case "SECTION":
			if u.section, err = url.PathUnescape(val); err != nil || u.uid == 0 {
				return u, false
			}
		case "PARTIAL":
			o, l, hasLen := strings.Cut(val, ".")
			var err error
			if u.origin, err = strconv.Atoi(o); err != nil || u.origin < 0 || u.uid == 0 {
				return u, false
			}
			if hasLen {
				if u.length, ok = parseNZNumber(l); !ok {
					return u, false
				}
			}
			u.partial = true
		case "EXPIRE":
			u.expire = val
		case "URLAUTH":
			parts := strings.SplitN(val, ":", 3)
			u.access = parts[0]
			if len(parts) == 3 {
				u.mech, u.token = parts[1], parts[2]
			} else if len(parts) != 1 {
				return u, false
			}
		default:
			return u, false
		}
	}
	return u, u.uid != 0
}

// owner is the address of the user whose mailbox u names: the URL user, completed with the host
// as domain when it has none ("imap://alice@example.org/...").
func (u imapURL) owner() string {
	if u.user == "" || strings.Contains(u.user, "@") {
		return u.user
	}
	host, _, _ := strings.Cut(u.host, ":")
	return u.user + "@" + host
}

// errBadURL means a URL names no message this session may read.
var errBadURL = errors.New("imap: bad URL")

// resolveURL returns the bytes u names in account accountID's mailboxes.
func (s *session) resolveURL(ctx context.Context, accountID uint32, u imapURL) ([]byte, error) {
	raw, err := s.loadURLMessage(ctx, accountID, u)
	if err != nil {
		return nil, err
	}
	data := raw
	if u.section != "" {
		section, fields, ok := parseHeaderFieldsSection(u.section)
		if !ok {
			if strings.Contains(u.section, "(") {
				return nil, errBadURL
			}
			section = u.section
		}
		data = extractBodySection(raw, section, fields)
	}
	return u.partialData(data), nil
}

// loadURLMessage returns the whole message u names in account accountID.
func (s *session) loadURLMessage(ctx context.Context, accountID uint32, u imapURL) ([]byte, error) {
	mbox, err := s.inbox.ResolveMailbox(ctx, accountID, u.mailbox)
	if errors.Is(err, storage.ErrNotFound) || err == nil && u.uidValidity != 0 && u.uidValidity != mbox.UIDValidity {
		return nil, errBadURL
	} else if err != nil {
		return nil, err
	}
	msgs, err := s.inbox.List(ctx, accountID, mbox.ID)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if m.UID == u.uid {
			return s.inbox.LoadMessage(ctx, m.Meta)
		}
	}
	return nil, errBadURL
}

// partialData applies the URL's ;PARTIAL=origin.length to data.
func (u imapURL) partialData(data []byte) []byte {
	if !u.partial {
		return data
	}
	data = data[min(u.origin, len(data)):]
	if u.length >= 0 {
		data = data[:min(u.length, len(data))]
	}
	return data
}

// encodeMUTF7 converts a UTF-8 mailbox name to the modified UTF-7 of the IMAP wire (RFC 3501 5.1.3).
func encodeMUTF7(name string) string {
	enc := base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,").WithPadding(base64.NoPadding)
	var b strings.Builder
	var run []rune
	flush := func() {
		if len(run) == 0 {
			return
		}
		u16 := utf16.Encode(run)
		buf := make([]byte, 0, 2*len(u16))
		for _, c := range u16 {
			buf = append(buf, byte(c>>8), byte(c))
		}
		b.WriteString("&" + enc.EncodeToString(buf) + "-")
		run = run[:0]
	}
	for _, r := range name {
		if r >= 0x20 && r <= 0x7e {
			flush()
			if r == '&' {
				b.WriteString("&-")
			} else {
				b.WriteRune(r)
			}
			continue
		}
		run = append(run, r)
	}
	flush()
	return b.String()
}
