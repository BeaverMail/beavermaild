// Package rfc5322 reads message header sections as RFC 5322 defines them, obsolete syntax included.
package rfc5322

import (
	"io"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// ReadMessage is net/mail.ReadMessage plus the obsolete field-name form of RFC 5322 4.5: white space
// before the colon ("From : x"), which a receiver MUST accept (section 4). net/textproto keys such a
// field as "From ", so From checks, DMARC and the IMAP ENVELOPE would each miss it while a conforming
// MUA shows it. Merged fields go after the regular ones; the order only matters when a field repeats.
func ReadMessage(r io.Reader) (*mail.Message, error) {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, err
	}
	for k, v := range msg.Header {
		name := strings.TrimRight(k, " \t")
		if name == k || name == "" {
			continue
		}
		name = textproto.CanonicalMIMEHeaderKey(name)
		msg.Header[name] = append(msg.Header[name], v...)
		delete(msg.Header, k)
	}
	return msg, nil
}

// obsZones are the zone names of RFC 5322 4.3; any other alphabetic zone, military letters
// included, SHOULD be read as -0000. net/mail reads them all as +0000 under their name.
var obsZones = map[string]string{
	"UT": "+0000", "GMT": "+0000",
	"EST": "-0500", "EDT": "-0400", "CST": "-0600", "CDT": "-0500",
	"MST": "-0700", "MDT": "-0600", "PST": "-0800", "PDT": "-0700",
}

// ParseDate is net/mail.ParseDate with the obsolete forms of RFC 5322 4.3 read as the section says:
// a 2-digit year is 2000+ below 50 and 1900+ from 50, a 3-digit year is 1900+, and the zone names
// above get their offset.
func ParseDate(s string) (time.Time, error) {
	f := strings.Fields(s)
	for i := 0; i+1 < len(f); i++ {
		if !isMonth(f[i]) {
			continue
		}
		if y, err := strconv.Atoi(f[i+1]); err == nil && y >= 0 {
			switch len(f[i+1]) {
			case 2:
				if y < 50 {
					y += 2000
				} else {
					y += 1900
				}
				f[i+1] = strconv.Itoa(y)
			case 3:
				f[i+1] = strconv.Itoa(y + 1900)
			}
		}
		// The zone follows the time of day, the first token with a colon after the year.
		for j := i + 2; j+1 < len(f); j++ {
			if !strings.Contains(f[j], ":") {
				continue
			}
			if z := f[j+1]; isAlpha(z) {
				if off, ok := obsZones[strings.ToUpper(z)]; ok {
					f[j+1] = off
				} else {
					f[j+1] = "-0000"
				}
			}
			break
		}
		break
	}
	return mail.ParseDate(strings.Join(f, " "))
}

func isMonth(s string) bool {
	switch strings.ToLower(s) {
	case "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec":
		return true
	}
	return false
}

func isAlpha(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return s != ""
}
