package imap

import "testing"

func TestParseAllBodyFetchesPartial(t *testing.T) {
	t.Parallel()

	got := parseAllBodyFetches("UID BODY.PEEK[TEXT]<0.500> BODY[1.MIME]<10.3> BODY[]")
	if len(got) != 3 {
		t.Fatalf("fetches %+v", got)
	}
	if !got[0].partial || got[0].origin != 0 || got[0].count != 500 || got[0].responseName() != "BODY[TEXT]<0>" {
		t.Fatalf("first %+v name %q", got[0], got[0].responseName())
	}
	if !got[1].partial || got[1].origin != 10 || got[1].count != 3 || got[1].responseName() != "BODY[1.MIME]<10>" {
		t.Fatalf("second %+v", got[1])
	}
	if got[2].partial || got[2].responseName() != "BODY[]" {
		t.Fatalf("third %+v", got[2])
	}
	// Malformed partials are ignored, as before.
	for _, arg := range []string{"BODY[]<5>", "BODY[]<1.0>", "BODY[]<a.b>", "BODY[]<1.2"} {
		if f := parseAllBodyFetches(arg); len(f) != 1 || f[0].partial {
			t.Fatalf("%q -> %+v", arg, f)
		}
	}
}

func TestPartialData(t *testing.T) {
	t.Parallel()

	data := []byte("0123456789")
	cases := []struct {
		origin, count int
		want          string
	}{
		{0, 4, "0123"},
		{8, 10, "89"},
		{10, 1, ""},
		{50, 1, ""},
	}
	for _, c := range cases {
		bs := bodySectionFetch{partial: true, origin: c.origin, count: c.count}
		if got := string(bs.partialData(data)); got != c.want {
			t.Fatalf("<%d.%d> = %q want %q", c.origin, c.count, got, c.want)
		}
	}
}
