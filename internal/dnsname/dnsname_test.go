package dnsname

import "testing"

func TestToASCII(t *testing.T) {
	for in, want := range map[string]string{
		"Example.ORG":                   "example.org",
		"münchen.example":               "xn--mnchen-3ya.example",
		"MÜNCHEN.example":               "xn--mnchen-3ya.example",
		"пример.рф":                     "xn--e1afmkfd.xn--p1ai",
		"ｅｘａｍｐｌｅ．com":                   "example.com", // fullwidth letters and dot
		"_dmarc.münchen.example":        "_dmarc.xn--mnchen-3ya.example",
		"sel._domainkey.bücher.example": "sel._domainkey.xn--bcher-kva.example",
		"xn--mnchen-3ya.example":        "xn--mnchen-3ya.example",
	} {
		if got := ToASCII(in); got != want {
			t.Errorf("ToASCII(%q) = %q, want %q", in, got, want)
		}
	}
}
