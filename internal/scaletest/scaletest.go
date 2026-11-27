// Package scaletest checks in tests that work grows linearly with its input, whatever the speed of
// the machine: a bound in seconds fails on a slow or busy runner and passes quadratic code on a fast one.
package scaletest

import (
	"math"
	"runtime"
	"testing"
	"time"
)

// minTime is the shortest run worth timing; shorter ones are mostly noise.
const minTime = 20 * time.Millisecond

// Linear fails t unless the work prepare(n) returns grows linearly with n. It times sizes n and 4n
// and fails when the larger takes over 8 times the smaller: linear work takes about 4 times,
// quadratic 16. First n doubles, at most 6 times, until the smaller run takes minTime. prepare
// builds the input outside the timing; the work it returns may check its result.
func Linear(t testing.TB, n int, prepare func(n int) func()) {
	t.Helper()
	LinearUpTo(t, n, math.MaxInt/8, prepare)
}

// LinearUpTo is Linear with the larger size never past max: where the code caps its input (a
// header truncated at its limit), a larger size would time the cap, not the work.
func LinearUpTo(t testing.TB, n, max int, prepare func(n int) func()) {
	t.Helper()
	smallRun := prepare(n)
	for i := 0; timed(smallRun) < minTime && i < 6 && 8*n <= max; i++ {
		n *= 2
		smallRun = prepare(n)
	}
	largeRun := prepare(4 * n)
	// Rounds alternate the sizes and each keeps its fastest: a burst of load from other tests
	// slows some rounds of both, not all rounds of one.
	small, large := time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)
	for range rounds {
		small = min(small, timed(smallRun))
		large = min(large, timed(largeRun))
	}
	if large > 8*small {
		t.Fatalf("size %d took %v, size %d took %v: %.1f times for 4 times the input, want about 4 (linear)",
			n, small, 4*n, large, float64(large)/float64(small))
	}
}

const rounds = 5

func timed(run func()) time.Duration {
	runtime.GC()
	start := time.Now()
	run()
	return time.Since(start)
}
