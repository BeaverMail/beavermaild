package mail

import (
	"context"
	"errors"
	"testing"
)

func TestSearchSortThreadStopOnCanceledContext(t *testing.T) {
	t.Parallel()

	msgs := []Message{{UID: 1}, {UID: 2}, {UID: 3}}
	expr := SearchExpr{Kind: SearchExprCrit, Crit: SearchCriteria{Text: "x"}}
	ctx, cancel := context.WithCancel(context.Background())
	loads := 0
	load := RawLoader(func(Message) ([]byte, error) {
		loads++
		cancel() // the client goes away while the first message is loaded
		return []byte("Subject: x\r\n\r\nx\r\n"), nil
	})

	if _, err := MatchSearchExprContext(ctx, msgs, expr, load); !errors.Is(err, context.Canceled) {
		t.Fatalf("search err %v", err)
	}
	if loads != 1 {
		t.Fatalf("search loaded %d messages after cancel", loads)
	}
	if _, err := SortMessagesContext(ctx, msgs, []SortKey{SortArrival}, false, expr, load); !errors.Is(err, context.Canceled) {
		t.Fatalf("sort err %v", err)
	}
	if _, err := ThreadReferencesContext(ctx, msgs, expr, load); !errors.Is(err, context.Canceled) {
		t.Fatalf("thread err %v", err)
	}
}
