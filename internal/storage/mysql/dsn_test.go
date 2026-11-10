package mysql

import (
	"strings"
	"testing"
)

func TestWithInterpolateParams(t *testing.T) {
	got, err := withInterpolateParams("alice:secret@tcp(192.0.2.1:3306)/beaver?parseTime=true&charset=utf8mb4")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"interpolateParams=true", "parseTime=true", "charset=utf8mb4", "tcp(192.0.2.1:3306)/beaver"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q lacks %q", got, want)
		}
	}
	// An explicit setting is kept as written.
	explicit := "alice:secret@tcp(192.0.2.1:3306)/beaver?interpolateParams=false"
	if got, _ := withInterpolateParams(explicit); got != explicit {
		t.Errorf("explicit setting rewritten: %q", got)
	}
}
