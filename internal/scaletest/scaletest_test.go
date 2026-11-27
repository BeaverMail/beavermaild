package scaletest

import (
	"testing"
)

// recorder is a testing.TB that notes a failure instead of stopping the test.
type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Helper()               {}
func (r *recorder) Fatalf(string, ...any) { r.failed = true }

var sink int

// Linear must tell linear work from quadratic work.
func TestLinear(t *testing.T) {
	linear := func(n int) func() {
		return func() {
			for i := range 100 * n {
				sink += i
			}
		}
	}
	quadratic := func(n int) func() {
		return func() {
			for i := range n {
				for j := range n {
					sink += i ^ j
				}
			}
		}
	}
	r := &recorder{TB: t}
	if Linear(r, 200000, linear); r.failed {
		t.Error("linear work reported as not linear")
	}
	r = &recorder{TB: t}
	if Linear(r, 4000, quadratic); !r.failed {
		t.Error("quadratic work not caught")
	}
}
