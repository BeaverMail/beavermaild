// SMTP EHLO extensions and MAIL/RCPT parameter parsing.
package smtp

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/BeaverMail/beaver/internal/mail"
)

// MailParams holds optional MAIL FROM ESMTP parameters.
type MailParams struct {
	Ret   mail.RetMode
	Envid string
	Body  string
}

// RcptParams holds optional RCPT TO ESMTP parameters.
type RcptParams struct {
	Notify mail.NotifyFlags
	Orcpt  string
}

// decodeSMTPBase64 decodes a client base64 line; raw input is accepted on decode failure.
func decodeSMTPBase64(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return line
	}
	return string(raw)
}

// parseMailArg extracts the envelope sender, SIZE, and DSN parameters from MAIL FROM.
func parseMailArg(arg string) (address string, declaredSize int, params MailParams, ok bool) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 5 || !strings.EqualFold(arg[:5], "FROM:") {
		return "", 0, MailParams{}, false
	}
	arg = strings.TrimSpace(arg[5:])
	lt := strings.IndexByte(arg, '<')
	if lt < 0 {
		return "", 0, MailParams{}, false
	}
	gt := strings.IndexByte(arg[lt:], '>')
	if gt < 0 {
		return "", 0, MailParams{}, false
	}
	address = strings.ToLower(strings.TrimSpace(arg[lt+1 : lt+gt]))
	for _, field := range strings.Fields(arg[lt+gt+1:]) {
		upper := strings.ToUpper(field)
		key, val, hasVal := strings.Cut(upper, "=")
		if !hasVal {
			if strings.Contains(upper, "=") {
				return "", 0, MailParams{}, false
			}
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
		default:
			return "", 0, MailParams{}, false
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
	arg = strings.TrimSpace(arg[3:])
	lt := strings.IndexByte(arg, '<')
	if lt < 0 {
		return "", RcptParams{}, false
	}
	gt := strings.IndexByte(arg[lt:], '>')
	if gt < 0 {
		return "", RcptParams{}, false
	}
	address = strings.ToLower(strings.TrimSpace(arg[lt+1 : lt+gt]))
	params.Notify = mail.NotifyDefault
	for _, field := range strings.Fields(arg[lt+gt+1:]) {
		upper := strings.ToUpper(field)
		key, val, hasVal := strings.Cut(upper, "=")
		if !hasVal {
			return "", RcptParams{}, false
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
		default:
			return "", RcptParams{}, false
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
