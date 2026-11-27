package mail

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// TestSearchKeyFoldedOncePerCommand: a key as long as a command line allows costs about what a
// short one does over the same messages, not the key times the messages (CVE-2026-107581 class).
// Measured in octets allocated, which load and the race detector do not change: folding a 60 KB
// key for each of 2000 messages allocates over 100 MB, once per command a few hundred KB.
func TestSearchKeyFoldedOncePerCommand(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector makes sync.Pool drop items on purpose: allocations do not measure the code")
	}
	raw := map[uint32]string{}
	var msgs []Message
	for i := uint32(1); i <= 2000; i++ {
		raw[i] = fmt.Sprintf("Subject: m%d\r\nFrom: a%d@example.com\r\n\r\nbody %d\r\n", i, i, i)
		msgs = append(msgs, Message{UID: i})
	}
	load := loaderOf(raw)
	long := strings.Repeat("lorem ipsum dolor sit amet ", 2200) + "zzz" // ~60 KB, never found
	allocated := func(c SearchCriteria) uint64 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		if got := MatchSearchWithLoader(msgs, c, load); len(got) != 0 {
			t.Fatalf("unexpected match %v", got)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	for name, mk := range map[string]func(string) SearchCriteria{
		"TEXT":    func(n string) SearchCriteria { return SearchCriteria{Text: n} },
		"SUBJECT": func(n string) SearchCriteria { return SearchCriteria{Subject: n} },
		"BODY":    func(n string) SearchCriteria { return SearchCriteria{Body: n} },
	} {
		short, longCost := allocated(mk("zzzqqq")), allocated(mk(long))
		if longCost > short+4<<20 {
			t.Errorf("%s: 60 KB key allocated %d KB, short key %d KB: the key is folded per message", name, longCost>>10, short>>10)
		}
	}
}
