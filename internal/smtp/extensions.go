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

// validXtext reports whether v is an xtext (RFC 3461 4): characters "!" to "~" except "+" and
// "=", or "+" followed by two upper-case hex digits.
func validXtext(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '+':
			if i+2 >= len(v) || !isUpperHex(v[i+1]) || !isUpperHex(v[i+2]) {
				return false
			}
			i += 2
		case c < '!' || c > '~' || c == '=':
			return false
		}
	}
	return true
}

func isUpperHex(c byte) bool { return '0' <= c && c <= '9' || 'A' <= c && c <= 'F' }

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
	for _, field := range strings.Fields(rest) {
		upper := strings.ToUpper(field)
		key, val, hasVal := strings.Cut(upper, "=")
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
			params.Envid = field[len(key)+1:]
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
	params.Notify = mail.NotifyDefault
	for _, field := range strings.Fields(rest) {
		upper := strings.ToUpper(field)
		key, val, hasVal := strings.Cut(upper, "=")
		if !hasVal {
			params.Unsupported = replyParamUnknown // RFC 5321 4.1.1.11
			continue
		}
		switch key {
		case "NOTIFY":
			notify, okNotify := mail.ParseNotify(val)
			if !okNotify {
				return "", RcptParams{}, false
			}
			params.Notify = notify
		case "ORCPT":
			params.Orcpt = field[len(key)+1:]
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
