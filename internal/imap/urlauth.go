// IMAP URLAUTH (RFC 4467) and URLAUTH=BINARY (RFC 5524): URLs that grant access to one message or
// part, signed with a per-mailbox key, for clients that pass mail by reference.
package imap

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// urlauthToken signs the URL rump (everything up to ";URLAUTH=access") with the mailbox key.
func urlauthToken(key []byte, rump string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(rump))
	return hex.EncodeToString(mac.Sum(nil))
}

// validAccess reports whether a is an RFC 4467 access identifier.
func validAccess(a string) bool {
	switch strings.ToLower(a) {
	case "authuser", "anonymous":
		return true
	}
	for _, p := range []string{"user+", "submit+"} {
		if len(a) > len(p) && strings.EqualFold(a[:len(p)], p) {
			return true
		}
	}
	return false
}

// cmdResetKey handles RESETKEY [mailbox [mechanism...]]: a new key for the mailbox, or no key at all
// for any mailbox; URLs signed with a dropped key stop working.
func (s *session) cmdResetKey(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	args, ok := urlauthArgs(arg)
	if !ok {
		return s.tagged(tag, "BAD RESETKEY syntax")
	}
	for _, mech := range args[min(1, len(args)):] {
		if !strings.EqualFold(mech, "INTERNAL") {
			return s.tagged(tag, "BAD unsupported URLAUTH mechanism")
		}
	}
	if len(args) == 0 {
		mboxes, err := s.inbox.ListMailboxes(ctx, s.principal.AccountID)
		if err != nil {
			return err
		}
		ids := make([]uint32, len(mboxes))
		for i, mb := range mboxes {
			ids[i] = mb.ID
		}
		if err := s.inbox.ResetURLAuthKeys(ctx, s.principal.AccountID, ids); err != nil {
			return err
		}
		return s.tagged(tag, "OK all keys removed")
	}
	mbox, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, args[0])
	if errors.Is(err, storage.ErrNotFound) {
		return s.tagged(tag, "NO mailbox does not exist")
	} else if err != nil {
		return err
	}
	if err := s.inbox.ResetURLAuthKeys(ctx, s.principal.AccountID, []uint32{mbox.ID}); err != nil {
		return err
	}
	if _, err := s.inbox.URLAuthKey(ctx, s.principal.AccountID, mbox.ID, true); err != nil {
		return err
	}
	return s.tagged(tag, "OK [URLMECH INTERNAL] key reset")
}

// cmdGenURLAuth signs "url mechanism" pairs: each URL names a message in one of this user's
// mailboxes and ends in ";URLAUTH=access". Any invalid pair makes the command BAD (RFC 4467 7).
func (s *session) cmdGenURLAuth(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	args, ok := urlauthArgs(arg)
	if !ok || len(args) == 0 || len(args)%2 != 0 {
		return s.tagged(tag, "BAD GENURLAUTH syntax")
	}
	var out []string
	for i := 0; i < len(args); i += 2 {
		raw, mech := args[i], args[i+1]
		u, ok := parseIMAPURL(raw)
		if !ok || !u.absolute || u.user == "" || u.mech != "" || !validAccess(u.access) ||
			!strings.HasSuffix(strings.ToUpper(raw), ";URLAUTH="+strings.ToUpper(u.access)) {
			return s.tagged(tag, "BAD invalid URLAUTH URL")
		}
		if !strings.EqualFold(mech, "INTERNAL") {
			return s.tagged(tag, "BAD unsupported URLAUTH mechanism")
		}
		if !strings.EqualFold(u.owner(), s.principal.Email()) {
			return s.tagged(tag, "BAD URL names another user")
		}
		if u.expire != "" {
			if _, err := time.Parse(time.RFC3339, u.expire); err != nil {
				return s.tagged(tag, "BAD invalid EXPIRE")
			}
		}
		mbox, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, u.mailbox)
		if errors.Is(err, storage.ErrNotFound) {
			return s.tagged(tag, "BAD mailbox does not exist")
		} else if err != nil {
			return err
		}
		key, err := s.inbox.URLAuthKey(ctx, s.principal.AccountID, mbox.ID, true)
		if err != nil {
			return err
		}
		out = append(out, quoteIMAPString(raw+":INTERNAL:"+urlauthToken(key, raw)))
	}
	if err := s.untagged("GENURLAUTH " + strings.Join(out, " ")); err != nil {
		return err
	}
	return s.tagged(tag, "OK GENURLAUTH completed")
}

// urlFetchItem is one URLFETCH argument: a URL, with RFC 5524 metadata items when parenthesized.
type urlFetchItem struct {
	url                    string
	ext                    bool
	body, binary, bodypart bool
}

// cmdURLFetch returns the data of each authorized URL; an invalid one gets NIL.
func (s *session) cmdURLFetch(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	items, ok := parseURLFetchArgs(arg)
	if !ok {
		return s.tagged(tag, "BAD URLFETCH syntax")
	}
	var b bytes.Buffer
	b.WriteString("* URLFETCH")
	// One message in memory at a time: each URL waits for a rawLoads slot and its part of the
	// response is written before the next one is loaded.
	for _, it := range items {
		if err := s.urlFetchItem(ctx, &b, it); err != nil {
			return err
		}
		if _, err := s.conn.Write(b.Bytes()); err != nil {
			return err
		}
		b.Reset()
	}
	b.WriteString("\r\n")
	if _, err := s.conn.Write(b.Bytes()); err != nil {
		return err
	}
	return s.tagged(tag, "OK URLFETCH completed")
}

// urlFetchItem appends one URL and its data to the URLFETCH response in b.
func (s *session) urlFetchItem(ctx context.Context, b *bytes.Buffer, it urlFetchItem) error {
	release, err := acquireRawLoad(ctx)
	if err != nil {
		return err
	}
	defer release()
	b.WriteString(" " + quoteIMAPString(it.url))
	u, raw, err := s.urlauthMessage(ctx, it.url)
	if errors.Is(err, errBadURL) {
		b.WriteString(" NIL")
		return nil
	} else if err != nil {
		return err
	}
	data, section := []byte{}, u.section
	if section != "" {
		fieldsSection, fields, ok := parseHeaderFieldsSection(section)
		if !ok {
			fieldsSection = section
		}
		data = extractBodySection(raw, fieldsSection, fields)
	} else {
		data = raw
	}
	data = u.partialData(data)
	if !it.ext {
		writeLiteral(b, " ", data)
		return nil
	}
	var dec []byte
	var decErr error
	if it.binary {
		dec, decErr = binarySection(raw, section)
	}
	if it.bodypart {
		// With BINARY the structure describes the decoded data the client receives (RFC 5524 3.2).
		b.WriteString(" (BODYPARTSTRUCTURE " + urlPartStructure(raw, section, it.binary && decErr == nil, dec) + ")")
	}
	if it.binary {
		b.WriteString(" (BINARY")
		if decErr != nil {
			b.WriteString(" NIL")
		} else {
			writeLiteral(b, " ", u.partialData(dec))
		}
		b.WriteString(")")
	}
	if it.body {
		b.WriteString(" (BODY")
		writeLiteral(b, " ", data)
		b.WriteString(")")
	}
	return nil
}

// urlauthMessage validates an URLAUTH URL against its owner's mailbox key and this session's
// identity, and loads the message it names; errBadURL covers every reason to answer NIL.
func (s *session) urlauthMessage(ctx context.Context, raw string) (imapURL, []byte, error) {
	u, ok := parseIMAPURL(raw)
	if !ok || !u.absolute || u.user == "" || !strings.EqualFold(u.mech, "INTERNAL") || len(u.token) < 32 {
		return u, nil, errBadURL
	}
	switch access := strings.ToLower(u.access); {
	case access == "authuser" || access == "anonymous":
	case strings.HasPrefix(access, "user+"):
		name, err := url.PathUnescape(u.access[len("user+"):])
		if err != nil || !strings.EqualFold(name, s.principal.Email()) {
			return u, nil, errBadURL
		}
	default:
		// "submit+": no session here is a submission entity.
		return u, nil, errBadURL
	}
	if u.expire != "" {
		t, err := time.Parse(time.RFC3339, u.expire)
		if err != nil || time.Now().After(t) {
			return u, nil, errBadURL
		}
	}
	acc, _, err := s.dir.ResolveEmail(ctx, u.owner())
	if errors.Is(err, storage.ErrNotFound) || err == nil && !acc.Active {
		return u, nil, errBadURL
	} else if err != nil {
		return u, nil, err
	}
	mbox, err := s.inbox.ResolveMailbox(ctx, acc.ID, u.mailbox)
	if errors.Is(err, storage.ErrNotFound) {
		return u, nil, errBadURL
	} else if err != nil {
		return u, nil, err
	}
	key, err := s.inbox.URLAuthKey(ctx, acc.ID, mbox.ID, false)
	if err != nil {
		return u, nil, err
	}
	rump := raw[:len(raw)-len(u.mech)-len(u.token)-2]
	if len(key) == 0 || !hmac.Equal([]byte(strings.ToLower(u.token)), []byte(urlauthToken(key, rump))) {
		return u, nil, errBadURL
	}
	msg, err := s.loadURLMessage(ctx, acc.ID, u)
	return u, msg, err
}

// urlPartStructure is the BODYSTRUCTURE of the part a URL section names (the message without one);
// with decoded it describes the part as decoded: no transfer encoding, the decoded size.
func urlPartStructure(raw []byte, section string, decoded bool, data []byte) string {
	if section == "" {
		return formatBodyStructure(raw)
	}
	path, ok := parseSectionPath(strings.ToUpper(section))
	if !ok {
		return "NIL"
	}
	part, ok := findPart(raw, path)
	if !ok {
		return "NIL"
	}
	if decoded {
		hdr := filterHeaderFields(part.header, []string{"Content-Transfer-Encoding"}, false)
		return formatBodyStructure(append(append([]byte{}, hdr...), data...))
	}
	return formatBodyStructure(append(append([]byte{}, part.header...), part.body...))
}

// writeLiteral appends sep and data as a literal, literal8 when it holds NUL.
func writeLiteral(b *bytes.Buffer, sep string, data []byte) {
	b.WriteString(sep)
	if bytes.IndexByte(data, 0) >= 0 {
		b.WriteByte('~')
	}
	fmt.Fprintf(b, "{%d}\r\n", len(data))
	b.Write(data)
}

// urlauthArgs splits space-separated astrings (quoted or atoms).
func urlauthArgs(arg string) ([]string, bool) {
	var out []string
	for rest := strings.TrimSpace(arg); rest != ""; rest = strings.TrimLeft(rest, " ") {
		if rest[0] == '"' {
			v, tail, ok := parseQuoted(rest)
			if !ok {
				return nil, false
			}
			out, rest = append(out, v), tail
			continue
		}
		v, tail, _ := strings.Cut(rest, " ")
		if strings.ContainsAny(v, "(){") {
			return nil, false
		}
		out, rest = append(out, v), tail
	}
	return out, true
}

// parseURLFetchArgs parses URLFETCH arguments: URLs, or "(url item...)" with RFC 5524 items.
func parseURLFetchArgs(arg string) ([]urlFetchItem, bool) {
	var items []urlFetchItem
	rest := strings.TrimSpace(arg)
	for rest != "" {
		if rest[0] != '(' {
			v, tail, _ := strings.Cut(rest, " ")
			if rest[0] == '"' {
				var ok bool
				if v, tail, ok = parseQuoted(rest); !ok {
					return nil, false
				}
			}
			items, rest = append(items, urlFetchItem{url: v}), strings.TrimLeft(tail, " ")
			continue
		}
		inner, tail, found := strings.Cut(rest[1:], ")")
		args, ok := urlauthArgs(inner)
		if !found || !ok || len(args) == 0 {
			return nil, false
		}
		it := urlFetchItem{url: args[0], ext: true}
		for _, p := range args[1:] {
			switch strings.ToUpper(p) {
			case "BODY":
				it.body = true
			case "BINARY":
				it.binary = true
			case "BODYPARTSTRUCTURE":
				it.bodypart = true
			default:
				return nil, false
			}
		}
		if it.body && it.binary { // RFC 5524 3.1
			return nil, false
		}
		items, rest = append(items, it), strings.TrimLeft(tail, " ")
	}
	return items, len(items) > 0
}
