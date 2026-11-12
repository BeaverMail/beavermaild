// SMTP EHLO extensions and MAIL/RCPT parameter parsing.
package smtp

import (
	"strconv"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// MailParams holds optional MAIL FROM ESMTP parameters.
type MailParams struct {
	Ret         mail.RetMode
	Envid       string
	Body        string
	SMTPUTF8    bool
	Unsupported string // non-empty: explicit reject reply for advertised extension params
}

// RcptParams holds optional RCPT TO ESMTP parameters.
type RcptParams struct {
	Notify      mail.NotifyFlags
	Orcpt       string
	Unsupported string
}

// validXtext reports whether v is an xtext (RFC 3461 4).
func validXtext(v string) bool {
	_, ok := mail.DecodeXtext(v)
	return ok
}

// parseMailArg extracts the envelope sender, SIZE, and DSN parameters from MAIL FROM.
func parseMailArg(arg string) (address string, declaredSize int, params MailParams, ok bool) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 5 || !strings.EqualFold(arg[:5], "FROM:") {
		return "", 0, MailParams{}, false
	}
	path, rest, ok := parsePath(arg[5:])
	if !ok {
		return "", 0, MailParams{}, false
	}
	address = normalizeEnvelopeAddress(path)
	seen := map[string]bool{}
	for _, field := range strings.Fields(rest) {
		upper := strings.ToUpper(field)
		key, val, hasVal := strings.Cut(upper, "=")
		// RET and ENVID at most once each (RFC 3461 4.5): 501.
		if (key == "RET" || key == "ENVID") && seen[key] {
			return "", 0, MailParams{}, false
		}
		seen[key] = true
		if !hasVal {
			if key == "SMTPUTF8" {
				params.SMTPUTF8 = true
				continue
			}
			params.Unsupported = replyParamUnknown
			continue
		}
		switch key {
		case "SIZE":
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 {
				return "", 0, MailParams{}, false
			}
			declaredSize = n
		case "RET":
			ret, okRet := mail.ParseRet(val)
			if !okRet {
				return "", 0, MailParams{}, false
			}
			params.Ret = ret
		case "ENVID":
			// Kept as received (xtext): relayed identical (RFC 3461 5.2.1), decoded only for the DSN.
			if params.Envid = field[len(key)+1:]; !mail.ValidEnvid(params.Envid) {
				return "", 0, MailParams{}, false
			}
		case "BODY":
			params.Body = val
		case "AUTH":
			// RFC 4954 5: a server advertising AUTH MUST accept the parameter, logged in or not. This
			// server trusts no client to assert another submitter, so it parses and drops it, which
			// the RFC allows (the message is then treated as AUTH=<>).
			if !validXtext(val) {
				return "", 0, MailParams{}, false
			}
		case "HOLD":
			params.Unsupported = replyParamNotSupported
		default:
			params.Unsupported = replyParamUnknown // RFC 5321 4.1.1.11
		}
	}
	return address, declaredSize, params, true
}

// parseRcptArg extracts the recipient address and DSN parameters from RCPT TO.
func parseRcptArg(arg string) (address string, params RcptParams, ok bool) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 3 || !strings.EqualFold(arg[:3], "TO:") {
		return "", RcptParams{}, false
	}
	path, rest, ok := parsePath(arg[3:])
	if !ok {
		return "", RcptParams{}, false
	}
	address = normalizeEnvelopeAddress(path)
	params.Notify = 0 // no NOTIFY: the default applies, and none is passed on (RFC 3461 5.2.1 (c))
	seen := map[string]bool{}
	for _, field := range strings.Fields(rest) {
		upper := strings.ToUpper(field)
		key, val, hasVal := strings.Cut(upper, "=")
		// NOTIFY and ORCPT at most once each (RFC 3461 4.5): 501.
		if (key == "NOTIFY" || key == "ORCPT") && seen[key] {
			return "", RcptParams{}, false
		}
		seen[key] = true
		if !hasVal {
			params.Unsupported = replyParamUnknown // RFC 5321 4.1.1.11
			continue
		}
		switch key {
		case "NOTIFY":
			notify, okNotify := mail.ParseNotify(val)
			if !okNotify || val == "" { // NOTIFY MUST have a value (RFC 3461 4.1)
				return "", RcptParams{}, false
			}
			params.Notify = notify
		case "ORCPT":
			if params.Orcpt = field[len(key)+1:]; !mail.ValidOrcpt(params.Orcpt) {
				return "", RcptParams{}, false
			}
		case "BY":
			params.Unsupported = replyParamNotSupported
		case "MT-PRIORITY":
			params.Unsupported = replyParamNotSupported
		case "SOLICIT":
			params.Unsupported = replyParamNotSupported
		default:
			params.Unsupported = replyParamUnknown // RFC 5321 4.1.1.11
		}
	}
	return address, params, true
}

// parseBDAT extracts the chunk size and optional LAST flag from a BDAT argument.
func parseBDAT(arg string) (size int, last bool, ok bool) {
	fields := strings.Fields(strings.TrimSpace(arg))
	if len(fields) == 0 || len(fields) > 2 {
		return 0, false, false
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil || n < 0 {
		return 0, false, false
	}
	if len(fields) == 2 {
		if !strings.EqualFold(fields[1], "LAST") {
			return 0, false, false
		}
		last = true
	}
	return n, last, true
}
