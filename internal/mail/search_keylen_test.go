package mail

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestSearchKeyFoldedOncePerCommand: a key as long as a command line allows costs about what a
// short one does over the same messages, not the key times the messages (CVE-2026-107581 class).
func TestSearchKeyFoldedOncePerCommand(t *testing.T) {
	raw := map[uint32]string{}
	var msgs []Message
	for i := uint32(1); i <= 2000; i++ {
		raw[i] = fmt.Sprintf("Subject: m%d\r\nFrom: a%d@example.com\r\n\r\nbody %d\r\n", i, i, i)
		msgs = append(msgs, Message{UID: i})
	}
	load := loaderOf(raw)
	long := strings.Repeat("lorem ipsum dolor sit amet ", 2200) + "zzz" // ~60 KB, never found
	cost := func(c SearchCriteria) time.Duration {
		best := time.Hour
		for range 3 {
			start := time.Now()
			if got := MatchSearchWithLoader(msgs, c, load); len(got) != 0 {
				t.Fatalf("unexpected match %v", got)
			}
			best = min(best, time.Since(start))
		}
		return best
	}
	for name, mk := range map[string]func(string) SearchCriteria{
		"TEXT":    func(n string) SearchCriteria { return SearchCriteria{Text: n} },
		"SUBJECT": func(n string) SearchCriteria { return SearchCriteria{Subject: n} },
	} {
		short, longCost := cost(mk("zzzqqq")), cost(mk(long))
		if longCost > 5*short+10*time.Millisecond {
			t.Errorf("%s: 60 KB key %v, short key %v: the key is folded per message", name, longCost, short)
		}
	}
}
