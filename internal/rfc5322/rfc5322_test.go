package rfc5322

import (
	"strings"
	"testing"
	"time"
)

// RFC 5322 4.5: obs-from = "From" *WSP ":" mailbox-list CRLF, and the same for every field.
func TestObsoleteFieldName(t *testing.T) {
	t.Parallel()
	msg, err := ReadMessage(strings.NewReader("From : a@bank.example\r\nfrom\t: b@attacker.example\r\nSubject: x\r\n\r\nbody"))
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.Header["From"]; len(got) != 2 {
		t.Fatalf("From fields: %q, want both obsolete forms", got)
	}
	if len(msg.Header) != 2 {
		t.Fatalf("header keys: %v", msg.Header)
	}
}

// RFC 5322 3.3 and 4.3, with the examples of appendix A.5 and A.6.3.
func TestParseDate(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"Fri, 21 Nov 1997 09:55:06 -0600":                                                          "1997-11-21T09:55:06-06:00",
		"Thu, 13 Feb 1969 23:32 -0330 (Newfoundland Time)":                                         "1969-02-13T23:32:00-03:30",
		"Thu,\r\n      13\r\n        Feb\r\n          1969\r\n      23:32\r\n               -0330": "1969-02-13T23:32:00-03:30",
		"21 Nov 97 09:55:06 GMT":                                                                   "1997-11-21T09:55:06Z",
		"Fri, 21 Nov 49 09:55:06 +0000":                                                            "2049-11-21T09:55:06Z",
		"Fri, 21 Nov 50 09:55:06 +0000":                                                            "1950-11-21T09:55:06Z",
		"Fri, 21 Nov 097 09:55:06 +0000":                                                           "1997-11-21T09:55:06Z",
		"Fri, 21 Nov 1997 09:55:06 EST":                                                            "1997-11-21T09:55:06-05:00",
		"Fri, 21 Nov 1997 09:55:06 pdt":                                                            "1997-11-21T09:55:06-07:00",
		"Fri, 21 Nov 1997 09:55:06 UT":                                                             "1997-11-21T09:55:06Z",
		"Fri, 21 Nov 1997 09:55:06 Z":                                                              "1997-11-21T09:55:06Z",
		"Fri, 21 Nov 1997 09:55:06 CEST":                                                           "1997-11-21T09:55:06Z",
	} {
		got, err := ParseDate(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		w, _ := time.Parse(time.RFC3339, want)
		if !got.Equal(w) {
			t.Errorf("%q: got %v, want %s", in, got, want)
		}
	}
	if _, err := ParseDate("not a date"); err == nil {
		t.Error("garbage parsed")
	}
}
