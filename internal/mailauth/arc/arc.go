// Package arc validates inbound Authenticated Received Chains per RFC 8617.
package arc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/dnsname"
)

const (
	maxARCSetCount = 50
	maxMessageSize = 32 << 20
	maxHeaderSize  = 256 << 10
	maxHeaderCount = 1000
	maxTagValue    = 64 << 10
)

// Result is a Chain Validation Status (RFC 8617 4.4): only none, pass and fail exist, and every
// error, DNS included, is a permanent fail (5.2.1).
type Result string

const (
	ResultPass Result = "pass"
	ResultFail Result = "fail"
	ResultNone Result = "none"
)

// LookupTXT resolves a DNS TXT owner name using the caller's context.
type LookupTXT func(context.Context, string) ([]string, error)

type header struct {
	name string
	raw  string
}

type message struct {
	headers []header
	body    []byte
}

type signature struct {
	header header
	tags   map[string]string
	i      int
}

type set struct {
	aar header
	ams signature
	as  signature
}

// Verify validates one ARC chain, using lookup for DKIM key TXT records. On pass, sealer is the
// d= of the most recent ARC-Seal: the one ADMD vouching for the chain (RFC 8617 9).
func Verify(ctx context.Context, r io.Reader, lookup LookupTXT) (result Result, sealer string) {
	msg, readErr := readMessage(r)
	sets, present, err := collectSets(msg.headers)
	if !present {
		return ResultNone, "" // also an unreadable header block: no chain to rely on either way
	}
	if readErr != nil || err != nil || lookup == nil {
		return ResultFail, ""
	}
	for i, s := range sets {
		wantCV := "pass"
		if i == 0 {
			wantCV = "none"
		}
		if s.as.tags["cv"] != wantCV { // also covers cv=fail on the newest set (5.2 steps 2, 3C)
			return ResultFail, ""
		}
	}
	keys := keyCache{lookup: lookup, seen: map[string]keyAnswer{}}
	if err := verifyAMS(ctx, msg, sets[len(sets)-1].ams, &keys); err != nil {
		return ResultFail, ""
	}
	for i := len(sets) - 1; i >= 0; i-- {
		if err := verifySeal(ctx, sets[:i+1], &keys); err != nil {
			return ResultFail, ""
		}
	}
	// d= may be a U-label (RFC 8617 4.1.4); trust lists hold A-labels.
	return ResultPass, dnsname.ToASCII(strings.TrimSuffix(sets[len(sets)-1].as.tags["d"], "."))
}

// keyCache resolves each selector._domainkey name once per message: sets of one chain often share
// a key, and a crafted chain could ask for the same name 51 times (RFC 8617 9.2).
type keyCache struct {
	lookup LookupTXT
	seen   map[string]keyAnswer
}

type keyAnswer struct {
	key crypto.PublicKey
	err error
}

func (c *keyCache) get(ctx context.Context, name string) (crypto.PublicKey, error) {
	if a, ok := c.seen[name]; ok {
		return a.key, a.err
	}
	records, err := c.lookup(ctx, name)
	var key crypto.PublicKey
	if err == nil {
		key, err = parsePublicKey(records)
	}
	c.seen[name] = keyAnswer{key, err}
	return key, err
}

// readMessage reads and parses a bounded RFC 5322 message.
func readMessage(r io.Reader) (message, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxMessageSize+1))
	if err != nil {
		return message{}, err
	}
	tooLarge := len(data) > maxMessageSize
	data = normalizeCRLF(data)
	at := bytes.Index(data, []byte("\r\n\r\n"))
	if at < 0 || at > maxHeaderSize {
		return message{}, errors.New("missing or oversized message header")
	}
	headers, err := parseHeaders(data[:at])
	if err != nil {
		return message{}, err
	}
	if tooLarge {
		// The header still tells whether a chain is there (then it fails: it cannot be checked).
		return message{headers: headers}, errors.New("message exceeds ARC verification limit")
	}
	return message{headers: headers, body: data[at+4:]}, nil
}

// normalizeCRLF converts accepted line endings to the canonical CRLF form.
func normalizeCRLF(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	return bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
}

// parseHeaders preserves folded fields while enforcing parser limits.
func parseHeaders(block []byte) ([]header, error) {
	lines := bytes.Split(block, []byte("\r\n"))
	headers := make([]header, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			return nil, errors.New("unexpected empty header line")
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(headers) == 0 {
				return nil, errors.New("orphaned header continuation")
			}
			headers[len(headers)-1].raw += "\r\n" + string(line)
			continue
		}
		if len(headers) >= maxHeaderCount {
			return nil, errors.New("too many message headers")
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return nil, errors.New("malformed message header")
		}
		name := strings.ToLower(string(line[:colon]))
		for _, c := range name {
			if c <= 32 || c >= 127 || c == ':' {
				return nil, errors.New("invalid header field name")
			}
		}
		headers = append(headers, header{name: name, raw: string(line)})
	}
	return headers, nil
}

// collectSets parses ARC fields and validates exact contiguous set membership.
func collectSets(headers []header) ([]set, bool, error) {
	byInstance := make(map[int]*set)
	present := false
	for _, h := range headers {
		if h.name != "arc-authentication-results" && h.name != "arc-message-signature" && h.name != "arc-seal" {
			continue
		}
		present = true
		i, err := instanceOf(h)
		if err != nil || i < 1 || i > maxARCSetCount {
			return nil, true, errors.New("invalid ARC instance")
		}
		s := byInstance[i]
		if s == nil {
			s = &set{}
			byInstance[i] = s
		}
		switch h.name {
		case "arc-authentication-results":
			if s.aar.raw != "" {
				return nil, true, errors.New("duplicate ARC authentication results")
			}
			s.aar = h
		case "arc-message-signature":
			if s.ams.header.raw != "" {
				return nil, true, errors.New("duplicate ARC message signature")
			}
			sig, err := parseSignature(h, false)
			if err != nil || sig.i != i {
				return nil, true, errors.New("invalid ARC message signature")
			}
			s.ams = sig
		case "arc-seal":
			if s.as.header.raw != "" {
				return nil, true, errors.New("duplicate ARC seal")
			}
			sig, err := parseSignature(h, true)
			if err != nil || sig.i != i {
				return nil, true, errors.New("invalid ARC seal")
			}
			s.as = sig
		}
	}
	if !present {
		return nil, false, nil
	}
	if len(byInstance) > maxARCSetCount {
		return nil, true, errors.New("too many ARC sets")
	}
	sets := make([]set, len(byInstance))
	for i := 1; i <= len(sets); i++ {
		s := byInstance[i]
		if s == nil || s.aar.raw == "" || s.ams.header.raw == "" || s.as.header.raw == "" {
			return nil, true, errors.New("incomplete or non-contiguous ARC chain")
		}
		sets[i-1] = *s
	}
	return sets, true, nil
}

// instanceOf extracts the leading ARC instance tag.
func instanceOf(h header) (int, error) {
	value, err := headerValue(h)
	if err != nil {
		return 0, err
	}
	semi := strings.IndexByte(value, ';')
	if semi < 0 {
		return 0, errors.New("missing ARC instance delimiter")
	}
	tag := strings.SplitN(value[:semi], "=", 2)
	if len(tag) != 2 || strings.TrimSpace(tag[0]) != "i" {
		return 0, errors.New("ARC instance must be first")
	}
	return parseInstanceValue(tag[1])
}

// parseInstanceValue accepts the ARC integer followed only by optional CFWS.
func parseInstanceValue(value string) (int, error) {
	value = strings.TrimSpace(value)
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, errors.New("missing ARC instance number")
	}
	rest := strings.TrimSpace(value[end:])
	for rest != "" {
		if rest[0] != '(' {
			return 0, errors.New("invalid ARC instance suffix")
		}
		depth, escaped, closeAt := 0, false, -1
		for i, c := range rest {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
			} else if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					closeAt = i
					break
				}
			}
		}
		if closeAt < 0 {
			return 0, errors.New("unterminated ARC comment")
		}
		rest = strings.TrimSpace(rest[closeAt+1:])
	}
	return strconv.Atoi(value[:end])
}

// parseSignature parses and checks the supported AMS or AS tag set.
func parseSignature(h header, seal bool) (signature, error) {
	value, err := headerValue(h)
	if err != nil {
		return signature{}, err
	}
	tags, err := parseTags(value)
	if err != nil {
		return signature{}, err
	}
	i, err := parseInstanceValue(tags["i"])
	if err != nil || i < 1 || i > maxARCSetCount {
		return signature{}, errors.New("invalid ARC signature instance")
	}
	required := []string{"i", "a", "b", "d", "s"}
	if seal {
		required = append(required, "cv")
	} else {
		required = append(required, "bh", "h")
	}
	for _, name := range required {
		if tags[name] == "" {
			return signature{}, fmt.Errorf("missing ARC signature tag %s", name)
		}
	}
	if a := strings.ToLower(tags["a"]); a != "rsa-sha256" && a != "ed25519-sha256" { // RFC 8301, 8463
		return signature{}, errors.New("unsupported ARC signature algorithm")
	}
	if seal {
		// Unknown tags are ignored (RFC 6376 3.2); only h= MUST fail a seal (RFC 8617 4.1.3).
		if _, ok := tags["h"]; ok {
			return signature{}, errors.New("ARC-Seal with h=")
		}
		cv := strings.ToLower(tags["cv"])
		if cv != "none" && cv != "pass" && cv != "fail" {
			return signature{}, errors.New("invalid ARC chain status")
		}
		tags["cv"] = cv
	}
	return signature{header: h, tags: tags, i: i}, nil
}

// headerValue unfolds a field value without altering significant spaces.
func headerValue(h header) (string, error) {
	colon := strings.IndexByte(h.raw, ':')
	if colon < 1 {
		return "", errors.New("malformed header")
	}
	value := strings.ReplaceAll(h.raw[colon+1:], "\r\n", "")
	if len(value) > maxTagValue {
		return "", errors.New("ARC field exceeds tag limit")
	}
	return strings.TrimSpace(value), nil
}

// parseTags parses a DKIM tag-list (RFC 6376 3.2): tag-spec *( ";" tag-spec ) [ ";" ]. Tag names
// are case-sensitive ("A=" is an unknown tag, not a=) and only the last tag-spec may be empty.
func parseTags(value string) (map[string]string, error) {
	tags := make(map[string]string)
	fields := strings.Split(value, ";")
	for n, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			if n == len(fields)-1 && n > 0 {
				break // trailing ";"
			}
			return nil, errors.New("empty ARC tag-spec")
		}
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			return nil, errors.New("malformed ARC signature tag")
		}
		name := strings.TrimSpace(parts[0])
		if name == "" {
			return nil, errors.New("empty ARC signature tag")
		}
		if _, ok := tags[name]; ok {
			return nil, errors.New("duplicate ARC signature tag")
		}
		tags[name] = strings.TrimSpace(parts[1])
	}
	return tags, nil
}

// verifyAMS validates the newest message signature and its body hash.
func verifyAMS(ctx context.Context, msg message, sig signature, keys *keyCache) error {
	signedFrom := false
	for _, name := range strings.Split(strings.ToLower(sig.tags["h"]), ":") {
		name = strings.TrimSpace(name)
		if name == "" || name == "authentication-results" || strings.HasPrefix(name, "arc-") {
			return errors.New("forbidden AMS signed header") // 4.1.2
		}
		signedFrom = signedFrom || name == "from"
	}
	if !signedFrom {
		return errors.New("AMS does not sign From") // RFC 6376 5.4
	}
	return verifyMessageSignature(ctx, msg, sig.header, sig.tags, keys)
}

// verifyMessageSignature is DKIM verification (RFC 6376 6.1.3) of a signature field over msg.
func verifyMessageSignature(ctx context.Context, msg message, sigHeader header, tags map[string]string, keys *keyCache) error {
	if c, ok := tags["c"]; ok && c == "" {
		return errors.New("empty c= tag") // c= needs a value; only an absent c= means simple/simple
	}
	headerCanon, bodyCanon, err := canonicalization(tags["c"])
	if err != nil {
		return err
	}
	body := canonicalizeBody(msg.body, bodyCanon)
	if l := tags["l"]; l != "" {
		// A shorter l= leaves text appended after signing unsigned; RFC 6376 8.2 lets verifiers
		// refuse it, and a passing chain earns trust.
		if n, err := strconv.Atoi(l); err != nil || n != len(body) {
			return errors.New("AMS body length does not cover the body")
		}
	}
	bodyHash := sha256.Sum256(body)
	wantBodyHash, err := decodeBase64(tags["bh"])
	if err != nil || !bytes.Equal(bodyHash[:], wantBodyHash) {
		return errors.New("AMS body hash mismatch")
	}
	var signed bytes.Buffer
	used := make(map[string]int)
	for _, name := range strings.Split(strings.ToLower(tags["h"]), ":") {
		name = strings.TrimSpace(name)
		if h, ok := selectHeader(msg.headers, name, used[name]); ok {
			signed.WriteString(canonicalizeHeader(h, headerCanon))
		}
		used[name]++ // a field listed and absent counts as the null string (RFC 6376 5.4.2)
	}
	signed.WriteString(canonicalizeSignature(sigHeader, headerCanon))
	return verifySignature(ctx, signed.Bytes(), tags, keys)
}

// selectHeader applies DKIM's bottom-up repeated-header selection rule.
func selectHeader(headers []header, name string, skip int) (header, bool) {
	for i := len(headers) - 1; i >= 0; i-- {
		if headers[i].name != name {
			continue
		}
		if skip > 0 {
			skip--
			continue
		}
		return headers[i], true
	}
	return header{}, false
}

// verifySeal validates the newest seal over all ARC sets in its scope (RFC 8617 5.1.1).
func verifySeal(ctx context.Context, sets []set, keys *keyCache) error {
	var signed bytes.Buffer
	for i, s := range sets {
		signed.WriteString(canonicalizeHeader(s.aar, "relaxed"))
		signed.WriteString(canonicalizeHeader(s.ams.header, "relaxed"))
		if i < len(sets)-1 {
			signed.WriteString(canonicalizeHeader(s.as.header, "relaxed"))
		}
	}
	signed.WriteString(canonicalizeSignature(sets[len(sets)-1].as.header, "relaxed"))
	return verifySignature(ctx, signed.Bytes(), sets[len(sets)-1].as.tags, keys)
}

// verifySignature checks b= over signed with the key at s._domainkey.d.
func verifySignature(ctx context.Context, signed []byte, tags map[string]string, keys *keyCache) error {
	domain := strings.TrimSuffix(strings.TrimSpace(tags["d"]), ".")
	selector := strings.TrimSpace(tags["s"])
	if domain == "" || selector == "" || strings.ContainsAny(domain+selector, "\r\n\t ") {
		return errors.New("invalid ARC key identity")
	}
	key, err := keys.get(ctx, selector+"._domainkey."+domain)
	if err != nil {
		return err
	}
	sig, err := decodeBase64(tags["b"])
	if err != nil {
		return errors.New("invalid ARC signature encoding")
	}
	digest := sha256.Sum256(signed)
	switch k := key.(type) {
	case *rsa.PublicKey:
		if strings.ToLower(tags["a"]) != "rsa-sha256" {
			return errors.New("key type does not match a=")
		}
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig)
	case ed25519.PublicKey:
		if strings.ToLower(tags["a"]) != "ed25519-sha256" {
			return errors.New("key type does not match a=")
		}
		if !ed25519.Verify(k, digest[:], sig) { // RFC 8463 3: Ed25519 over the SHA-256 hash
			return errors.New("ARC signature mismatch")
		}
		return nil
	}
	return errors.New("unsupported ARC key")
}

// parsePublicKey parses one bounded DKIM key record: RSA of 1024-8192 bits (RFC 8301) or Ed25519
// (RFC 8463).
func parsePublicKey(records []string) (crypto.PublicKey, error) {
	var record string
	for _, candidate := range records {
		if strings.Contains(strings.ToLower(candidate), "p=") {
			if record != "" {
				return nil, errors.New("multiple ARC key records")
			}
			record = candidate
		}
	}
	if record == "" || len(record) > maxTagValue {
		return nil, errors.New("ARC key record not found")
	}
	tags, err := parseTags(record)
	if err != nil {
		return nil, err
	}
	if v := strings.ToUpper(tags["v"]); v != "" && v != "DKIM1" {
		return nil, errors.New("unsupported ARC key version")
	}
	if h := strings.ToLower(tags["h"]); h != "" && !colonListContains(h, "sha256") {
		return nil, errors.New("ARC key disallows SHA-256")
	}
	if service := strings.ToLower(tags["s"]); service != "" && !colonListContains(service, "*") && !colonListContains(service, "email") {
		return nil, errors.New("ARC key disallows email service")
	}
	der, err := decodeBase64(tags["p"])
	if err != nil || len(der) == 0 {
		return nil, errors.New("invalid or revoked ARC key")
	}
	switch strings.ToLower(tags["k"]) {
	case "", "rsa":
	case "ed25519":
		if len(der) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 key")
		}
		return ed25519.PublicKey(der), nil
	default:
		return nil, errors.New("unsupported ARC key type")
	}
	var key *rsa.PublicKey
	if parsed, parseErr := x509.ParsePKIXPublicKey(der); parseErr == nil {
		key, _ = parsed.(*rsa.PublicKey)
	}
	if key == nil {
		key, err = x509.ParsePKCS1PublicKey(der)
		if err != nil {
			return nil, errors.New("invalid ARC RSA key")
		}
	}
	if key.N.BitLen() < 1024 || key.N.BitLen() > 8192 || key.E < 3 {
		return nil, errors.New("unsafe ARC RSA key size")
	}
	return key, nil
}

// colonListContains reports whether a DKIM colon-delimited list has a value.
func colonListContains(list, value string) bool {
	for _, item := range strings.Split(list, ":") {
		if strings.TrimSpace(item) == value {
			return true
		}
	}
	return false
}

// canonicalization parses the DKIM c= header/body algorithms.
func canonicalization(value string) (string, string, error) {
	if value == "" {
		return "simple", "simple", nil
	}
	parts := strings.Split(strings.ToLower(strings.TrimSpace(value)), "/")
	if len(parts) > 2 {
		return "", "", errors.New("invalid AMS canonicalization")
	}
	headerCanon, bodyCanon := parts[0], "simple"
	if len(parts) == 2 {
		bodyCanon = parts[1]
	}
	if (headerCanon != "simple" && headerCanon != "relaxed") || (bodyCanon != "simple" && bodyCanon != "relaxed") {
		return "", "", errors.New("unsupported AMS canonicalization")
	}
	return headerCanon, bodyCanon, nil
}

// canonicalizeHeader applies DKIM simple or relaxed header canonicalization (RFC 6376 3.4.1, 3.4.2).
func canonicalizeHeader(h header, mode string) string {
	return canonicalizeRaw(h.raw, mode) + "\r\n"
}

// canonicalizeSignature is the signature field as hashed: b= empty and no trailing CRLF (RFC 6376
// 3.7). The CRLF was included: no chain sealed by another implementation could verify.
func canonicalizeSignature(h header, mode string) string {
	return canonicalizeRaw(stripBValue(h.raw), mode)
}

func canonicalizeRaw(raw, mode string) string {
	if mode == "simple" {
		return raw
	}
	colon := strings.IndexByte(raw, ':')
	value := strings.ReplaceAll(raw[colon+1:], "\r\n", "")
	value = compressWSP(strings.Trim(value, " \t"))
	return strings.ToLower(raw[:colon]) + ":" + value
}

// stripBValue removes only the b= value while preserving surrounding syntax.
func stripBValue(raw string) string {
	colon := strings.IndexByte(raw, ':')
	if colon < 0 {
		return raw
	}
	start := colon + 1
	for start < len(raw) {
		semi := strings.IndexByte(raw[start:], ';')
		end := len(raw)
		if semi >= 0 {
			end = start + semi
		}
		field := raw[start:end]
		eq := strings.IndexByte(field, '=')
		if eq >= 0 && strings.EqualFold(strings.TrimSpace(field[:eq]), "b") {
			valueStart := start + eq + 1
			return raw[:valueStart] + raw[end:]
		}
		if semi < 0 {
			break
		}
		start = end + 1
	}
	return raw
}

// canonicalizeBody applies DKIM simple or relaxed body canonicalization.
func canonicalizeBody(body []byte, mode string) []byte {
	body = normalizeCRLF(body)
	lines := bytes.Split(body, []byte("\r\n"))
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if mode == "relaxed" {
		for i, line := range lines {
			lines[i] = []byte(compressWSP(strings.TrimRight(string(line), " \t")))
		}
	}
	for len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		if mode == "relaxed" {
			return nil // RFC 6376 3.4.4: an empty body is the null input; only simple makes it CRLF
		}
		return []byte("\r\n")
	}
	return append(bytes.Join(lines, []byte("\r\n")), '\r', '\n')
}

// compressWSP reduces each run of SP or HTAB to one SP.
func compressWSP(value string) string {
	var out strings.Builder
	space := false
	for _, r := range value {
		if r == ' ' || r == '\t' {
			space = true
			continue
		}
		if space {
			out.WriteByte(' ')
			space = false
		}
		out.WriteRune(r)
	}
	if space {
		out.WriteByte(' ')
	}
	return out.String()
}

// decodeBase64 decodes DKIM base64 after removing folding whitespace.
func decodeBase64(value string) ([]byte, error) {
	value = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, value)
	return base64.StdEncoding.DecodeString(value)
}
