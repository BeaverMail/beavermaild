package imap

import "testing"

func TestCompactRuns(t *testing.T) {
	if got := compactRuns([]uint32{1, 2, 3, 5, 7, 8, 6}); got != "1:3,5,7:8,6" {
		t.Fatalf("got %q", got)
	}
}

func TestCutReturnOpts(t *testing.T) {
	for _, tc := range []struct {
		arg         string
		want        returnOpts
		rest        string
		present, ok bool
	}{
		{"ALL", returnOpts{}, "ALL", false, true},
		{"RETURN () ALL", returnOpts{all: true}, " ALL", true, true},
		{"return (min Max) 1:3", returnOpts{min: true, max: true}, " 1:3", true, true},
		{"RETURN (SAVE) ALL", returnOpts{}, "", true, false},
		{"RETURN (MIN ALL", returnOpts{}, "", true, false},
	} {
		o, rest, present, ok := cutReturnOpts(tc.arg)
		if present != tc.present || ok != tc.ok || (ok && (o != tc.want || rest != tc.rest)) {
			t.Errorf("%q: %+v %q %v %v", tc.arg, o, rest, present, ok)
		}
	}
}
