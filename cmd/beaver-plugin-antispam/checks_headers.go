// Derived from rspamd (https://github.com/rspamd/rspamd), Copyright (c) Vsevolod Stakhov and the
// rspamd contributors, Apache License 2.0 (LICENSES/Apache-2.0.txt): rules/{mid,misc,subject_checks,headers_checks}.lua and rules/regexp/headers.lua.
// Includes regular expressions from Apache SpamAssassin, Copyright The Apache Software Foundation.
// Translated to Go and modified for BeaverMail; see NOTICE.

// Header checks: Message-ID, Date, Subject, From / Reply-To / To and structural header rules.
package main

import (
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/publicsuffix"
)

// esld returns the registrable domain (rspamd get_tld), or d itself when unknown.
func esld(d string) string {
	if e, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(d, ".")); err == nil {
		return e
	}
	return d
}

var (
	midBareIP    = regexp.MustCompile(`@\d+\.\d+\.\d+\.\d+>$`)
	midNotFQDN   = regexp.MustCompile(`@[^.]+>?$`)
	midBrackets  = regexp.MustCompile(`^<[^>]+>$`)
	midIPLiteral = regexp.MustCompile(`@\[\d+\.\d+\.\d+\.\d+\]`)
	midRHS       = regexp.MustCompile(`@([^>]+)>?$`)
	midRealm     = regexp.MustCompile(`@([a-z]+)>?$`)
)

// checkMID ports rules/mid.lua.
func checkMID(m *message, r *result) {
	mid, ok := m.get("Message-ID")
	if !ok {
		r.add("MISSING_MID", 1)
		return
	}
	if midBareIP.MatchString(mid) {
		r.add("MID_BARE_IP", 1)
	}
	if midNotFQDN.MatchString(mid) {
		r.add("MID_RHS_NOT_FQDN", 1)
	}
	if !midBrackets.MatchString(mid) {
		r.add("MID_MISSING_BRACKETS", 1)
	}
	if midIPLiteral.MatchString(mid) {
		r.add("MID_RHS_IP_LITERAL", 1)
	}
	lmid := strings.ToLower(mid)
	md := ""
	if s := midRHS.FindStringSubmatch(mid); s != nil {
		md = strings.ToLower(s[1])
	}
	from, _, _ := m.addrs("From")
	fd := ""
	if len(from) > 0 {
		fd = domainOf(from[0].Address)
	}
	if fd != "" {
		switch {
		case strings.Contains(lmid, strings.ToLower(from[0].Address)):
			r.add("MID_CONTAINS_FROM", 1)
		case md != "" && fd == md:
			r.add("MID_RHS_MATCH_FROM", 1)
		case md != "" && esld(md) == esld(fd):
			r.add("MID_RHS_MATCH_FROMTLD", 1)
		}
		if s := midRealm.FindStringSubmatch(mid); s != nil {
			if user, _, _ := strings.Cut(from[0].Address, "@"); s[1] == user {
				r.add("MID_END_EQ_FROM_USER_PART", 1)
			}
		}
	}
	to, _, _ := m.addrs("To")
	if len(to) > 0 {
		if td := domainOf(to[0].Address); td != "" && fd != td {
			if strings.Contains(lmid, strings.ToLower(to[0].Address)) {
				r.add("MID_CONTAINS_TO", 1)
			} else if md != "" && td == md {
				r.add("MID_RHS_MATCH_TO", 1)
			}
		}
	}
}

// checkDate ports the DATE_CB rule of rules/misc.lua (receipt time = now).
func checkDate(m *message, now time.Time, r *result) {
	v, ok := m.get("Date")
	if !ok || v == "" {
		r.add("MISSING_DATE", 1)
		return
	}
	t, err := mail.ParseDate(v)
	if err != nil {
		r.add("INVALID_DATE", 1)
		return
	}
	diff := now.Sub(t)
	switch {
	case diff > 24*time.Hour:
		r.add("DATE_IN_PAST", 1, strconv.Itoa(int(diff.Hours())))
	case -diff > 2*time.Hour:
		r.add("DATE_IN_FUTURE", 1, strconv.Itoa(int(-diff.Hours())))
	}
}

var subjectReplyRe = regexp.MustCompile(`(?i)^(?:(?:Re|Fwd|Fw|Aw|Antwort|Sv):\s*)+(.+)$`)

// isUppercase mirrors rspamd_util.is_uppercase: letters present, none lowercase.
func isUppercase(s string) bool {
	letters := false
	for _, c := range s {
		if unicode.IsLower(c) {
			return false
		}
		letters = letters || unicode.IsUpper(c)
	}
	return letters
}

// checkSubject ports rules/subject_checks.lua.
func checkSubject(m *message, r *result) {
	sbj, ok := m.decoded("Subject")
	if !ok {
		return
	}
	if s := subjectReplyRe.FindStringSubmatch(sbj); s != nil {
		sbj = s[1]
	}
	l := utf8.RuneCountInString(sbj)
	if isUppercase(sbj) {
		r.add("SUBJ_ALL_CAPS", min(float64(l)/40, 1), strconv.Itoa(l))
	}
	if l > 200 {
		r.add("LONG_SUBJ", min(float64(l)/400, 1), strconv.Itoa(l))
	}
}

var (
	encodedB64     = regexp.MustCompile(`(?i)=\?\S+\?B\?`)
	encodedQP      = regexp.MustCompile(`(?i)=\?\S+\?Q\?`)
	needsMIME      = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x{10FFFF}]`)
	httpInFrom     = regexp.MustCompile(`(^|"|'|\s)[hH][tT][tT][pP][sS]?(:|=3A)//\S`)
	noSpaceInFrom  = regexp.MustCompile(`\S<[-\w.]+@[-\w.]+>`)
	toWrapped      = regexp.MustCompile(`<\s[-.\w]+@[-.\w]+\s>`)
	undiscRcpt     = regexp.MustCompile(`(?i)^<?"?undisclosed[- ]recipients?\b.*:`)
	saneMsgID      = regexp.MustCompile(`^<?[^<>\\ \t\n\r\x0b\x{80}-\x{10FFFF}]+@[^<>\\ \t\n\r\x0b\x{80}-\x{10FFFF}]+>?\s*$`)
	msgIDComment   = regexp.MustCompile(`\(.*\)`)
	fakeReply      = regexp.MustCompile(`(?i)^(antw|atb|aw|bls|odp|res?|rif|sv|ynt)[. ]*:`)
	trackerID      = regexp.MustCompile(`(?is)^[a-z0-9]{6,24}[-_a-z0-9]{12,36}[a-z0-9]{6,24}\s*\z`)
	titleRe        = regexp.MustCompile(`^(mrs?|dr)[.\s]`)
	currencyRe     = regexp.MustCompile(`\p{Sc}`)
	cteCaseRe      = regexp.MustCompile(`^[78]B`)
	phposFake      = regexp.MustCompile(`(?i)^\d{7}:`)
	mailchimpMailr = regexp.MustCompile(`(?i)^Mailchimp Mailer\b`)
)

func hasRawBytes(s string) bool { return needsMIME.MatchString(s) }

// checkHeaders ports rules/regexp/headers.lua and rules/headers_checks.lua header rules.
func checkHeaders(m *message, req *request, r *result) {
	// *_NEEDS_ENCODING / *_EXCESS_* (rspamd non-UTF8 mode)
	mailchimp := false
	if xm, ok := m.get("X-Mailer"); ok {
		mailchimp = mailchimpMailr.MatchString(xm)
	}
	for _, e := range []struct{ hdr, needs, b64, qp string }{
		{"Subject", "SUBJECT_NEEDS_ENCODING", "SUBJ_EXCESS_BASE64", "SUBJ_EXCESS_QP"},
		{"From", "FROM_NEEDS_ENCODING", "FROM_EXCESS_BASE64", "FROM_EXCESS_QP"},
		{"To", "TO_NEEDS_ENCODING", "TO_EXCESS_BASE64", "TO_EXCESS_QP"},
		{"Reply-To", "", "REPLYTO_EXCESS_BASE64", "REPLYTO_EXCESS_QP"},
		{"Cc", "", "CC_EXCESS_BASE64", "CC_EXCESS_QP"},
	} {
		raw, ok := m.get(e.hdr)
		if !ok {
			continue
		}
		isB64, isQP := encodedB64.MatchString(raw), encodedQP.MatchString(raw)
		if e.needs != "" && !isB64 && !isQP && hasRawBytes(raw) {
			r.add(e.needs, 1)
		}
		dec := decodeWords(raw)
		if isB64 && !hasRawBytes(dec) {
			r.add(e.b64, 1)
		}
		if isQP && !hasRawBytes(dec) && !((e.hdr == "Subject" || e.hdr == "Reply-To") && mailchimp) {
			r.add(e.qp, 1)
		}
	}
	if from, ok := m.decoded("From"); ok {
		if httpInFrom.MatchString(from) {
			r.add("R_HTTP_URL_IN_FROM", 1)
		}
	}
	if from, ok := m.get("From"); ok && noSpaceInFrom.MatchString(from) {
		r.add("R_NO_SPACE_IN_FROM", 1)
	}
	if to, ok := m.get("To"); ok {
		if toWrapped.MatchString(to) {
			r.add("TO_WRAPPED_IN_SPACES", 1)
		}
		if undiscRcpt.MatchString(decodeWords(to)) {
			r.add("R_UNDISC_RCPT", 1)
		}
	} else {
		r.add("MISSING_TO", 1)
	}
	if sbj, ok := m.decoded("Subject"); !ok {
		r.add("MISSING_SUBJECT", 1)
	} else {
		if sbj == "" {
			r.add("EMPTY_SUBJECT", 1)
		}
		if fakeReply.MatchString(sbj) && !m.has("In-Reply-To") && !m.has("References") {
			r.add("FAKE_REPLY", 1)
		}
		if strings.HasSuffix(strings.TrimRightFunc(sbj, unicode.IsSpace), "?") {
			r.add("SUBJECT_ENDS_QUESTION", 1)
		}
		if currencyRe.MatchString(sbj) {
			r.add("SUBJECT_HAS_CURRENCY", 1)
		}
		if sbj != "" && unicode.IsSpace(rune(sbj[len(sbj)-1])) {
			r.add("SUBJECT_ENDS_SPACES", 1)
		}
	}
	if mid, ok := m.decoded("Message-ID"); ok && !saneMsgID.MatchString(mid) && !msgIDComment.MatchString(mid) {
		r.add("INVALID_MSGID", 1)
	}
	for _, h := range []struct{ name, sym string }{{"From", "HEADER_FROM_EMPTY_DELIMITER"}, {"To", "HEADER_TO_EMPTY_DELIMITER"},
		{"Cc", "HEADER_CC_EMPTY_DELIMITER"}, {"Reply-To", "HEADER_REPLYTO_EMPTY_DELIMITER"}, {"Date", "HEADER_DATE_EMPTY_DELIMITER"}} {
		for _, x := range m.all(h.name) {
			if x.emptySep {
				r.add(h.sym, 1)
			}
		}
	}
	if v, ok := m.get("Content-Transfer-Encoding"); ok && cteCaseRe.MatchString(v) {
		r.add("CTE_CASE", 1)
	}
	if v, ok := m.get("Content-Type"); ok && strings.HasSuffix(v, ";") {
		r.add("CT_EXTRA_SEMI", 1)
	}
	if v, ok := m.decoded("Content-Description"); ok && strings.EqualFold(v, "Mail message body") {
		r.add("CD_MM_BODY", 1)
	}
	if v, ok := m.decoded("X-PHP-Originating-Script"); ok && phposFake.MatchString(v) {
		r.add("X_PHPOS_FAKE", 1)
	}
	if m.has("List-Unsubscribe") {
		r.add("HAS_LIST_UNSUB", 1)
	}
	if m.hasExactCase("Mime-Version") {
		r.add("MV_CASE", 1)
	}
	if m.hasExactCase("X-mailer") {
		r.add("XM_CASE", 1)
	}
	checkUniqueHeaders(m, r)
	checkFromHeaders(m, req, r)
	checkReplyTo(m, r)
	checkRcptHeaders(m, req, r)
}

// headersUnique is the MULTIPLE_UNIQUE_HEADERS weight table of headers_checks.lua.
var headersUnique = map[string]float64{"Content-Type": 1, "Content-Transfer-Encoding": 1, "Date": 0.1, "From": 1,
	"Sender": 1, "Reply-To": 1, "To": 0.2, "Cc": 0.1, "Bcc": 0.1, "Message-ID": 0.7, "In-Reply-To": 0.7,
	"References": 0.3, "Subject": 0.7}

func checkUniqueHeaders(m *message, r *result) {
	found, maxMult := 0, 0.0
	var dup []string
	for h, mult := range headersUnique {
		n := len(m.all(h))
		found += n
		if n > 1 {
			dup = append(dup, h)
			maxMult = max(maxMult, mult)
		}
	}
	switch {
	case len(dup) > 0:
		r.add("MULTIPLE_UNIQUE_HEADERS", maxMult, dup...)
	case found == 0:
		r.add("MISSING_ESSENTIAL_HEADERS", 1)
	}
	if v, ok := m.get("From"); !ok || v == "" {
		r.add("MISSING_FROM", 1)
	}
}

// has8bit reports raw 8-bit bytes in an address (rspamd's 8bit address flag, non-UTF8 mode).
func has8bit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

func checkFromHeaders(m *message, req *request, r *result) {
	if req.From != "" {
		if _, err := mail.ParseAddress("<" + strings.Trim(req.From, "<>") + ">"); err != nil {
			r.add("ENVFROM_INVALID", 1)
		}
	}
	from, present, ok := m.addrs("From")
	if !present {
		return
	}
	if !ok {
		r.add("FROM_INVALID", 1)
		return
	}
	if len(from) > 1 {
		r.add("MULTIPLE_FROM", 1)
	}
	f := from[0]
	if has8bit(f.Address) {
		r.add("INVALID_FROM_8BIT", 1)
	}
	if f.Name != "" {
		n := strings.ToLower(f.Name)
		if strings.EqualFold(f.Name, f.Address) {
			r.add("FROM_DN_EQ_ADDR", 1)
		} else {
			if t := titleRe.FindStringSubmatch(n); t != nil {
				r.add("FROM_NAME_HAS_TITLE", 1, t[1])
			}
			if strings.Contains(n, "  ") || strings.Contains(n, "\t") {
				r.add("FROM_NAME_EXCESS_SPACE", 1)
			}
		}
	}
	if v, ok := m.get("X-Confirm-Reading-To"); ok {
		if l, err := mail.ParseAddressList(v); err == nil && !strings.Contains(f.Address, l[0].Address) {
			r.add("HEADER_RCONFIRM_MISMATCH", 1)
		}
	}
	if v, ok := m.get("Disposition-Notification-To"); ok {
		l, err := mail.ParseAddressList(v)
		switch {
		case err == nil && req.From == "":
			r.add("HEADER_FORGED_MDN", 1)
		case err == nil:
			match := false
			for _, a := range l {
				match = match || strings.EqualFold(a.Address, strings.Trim(req.From, "<>"))
			}
			if !match {
				r.add("HEADER_FORGED_MDN", 1)
			}
		}
	}
}

// checkReplyTo ports CHECK_REPLYTO of headers_checks.lua (scored symbols only).
func checkReplyTo(m *message, r *result) {
	raw, ok := m.get("Reply-To")
	if !ok {
		return
	}
	rt, err := (&mail.AddressParser{WordDecoder: &wordDec}).ParseList(raw)
	if err != nil || len(rt) == 0 || rt[0].Address == "" {
		r.add("REPLYTO_UNPARSEABLE", 1)
		return
	}
	user, dom, okAt := strings.Cut(rt[0].Address, "@")
	if !okAt || user == "" || dom == "" {
		r.add("REPLYTO_INVALID", 1)
	}
	if len(user) > 64 {
		r.add("REPLYTO_LOCALPART_LONG", 1, strconv.Itoa(len(user)))
	}
	if len(dom) > 255 {
		r.add("REPLYTO_DOMAIN_LONG", 1, strconv.Itoa(len(dom)))
	}
	if from, _, ok := m.addrs("From"); ok {
		if t := titleRe.FindStringSubmatch(strings.ToLower(from[0].Name)); t != nil &&
			strings.HasPrefix(strings.ToLower(rt[0].Address), t[1]) {
			r.add("REPLYTO_EMAIL_HAS_TITLE", 1)
		}
		fromRaw, _ := m.get("From")
		if fromRaw == raw {
			return
		}
	} else {
		return
	}
	to, _, _ := m.addrs("To")
	if len(to) > 0 && strings.EqualFold(to[0].Address, rt[0].Address) &&
		!m.has("List-Unsubscribe") && !m.has("X-To-Get-Off-This-List") && !m.has("X-List") && !m.has("Auto-Submitted") {
		r.add("REPLYTO_EQ_TO_ADDR", 1)
	}
}

// checkRcptHeaders ports TO_DN_RECIPIENTS and INVALID_RCPT_8BIT.
func checkRcptHeaders(m *message, _ *request, r *result) {
	for _, h := range []string{"To", "Cc"} {
		raw, _ := m.get(h)
		if has8bit(raw) {
			if l, _, ok := m.addrs(h); ok {
				for _, a := range l {
					if has8bit(a.Address) {
						r.add("INVALID_RCPT_8BIT", 1)
					}
				}
			}
		}
		l, _, _ := m.addrs(h)
		for _, a := range l {
			if n := strings.ToLower(a.Name); h == "To" && (n == "recipient" || n == "recipients") {
				r.add("TO_DN_RECIPIENTS", 1)
			}
		}
	}
}
