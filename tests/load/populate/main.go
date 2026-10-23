// Command populate fills a BeaverMail data dir with synthetic tenants, accounts and messages
// for load testing. It writes through the normal delivery path (directory + Inbox.Deliver).
//
//	go run ./tests/load/populate -c .data/load/config.json -tenants 100 -accounts 3 -per 6000 -big 100000
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BeaverMail/beaver/internal/runtime"
)

var words = strings.Fields(`lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor
incididunt ut labore et dolore magna aliqua enim ad minim veniam quis nostrud exercitation ullamco laboris
nisi aliquip ex ea commodo consequat duis aute irure in reprehenderit voluptate velit esse cillum fugiat
nulla pariatur excepteur sint occaecat cupidatat non proident sunt culpa qui officia deserunt mollit anim
id est laborum ordine consegna preventivo riunione progetto cliente fornitore pagamento scadenza contratto`)

func main() {
	cfgPath := flag.String("c", "", "config path")
	tenants := flag.Int("tenants", 100, "tenants (one domain each)")
	accounts := flag.Int("accounts", 3, "accounts per tenant")
	per := flag.Int("per", 1000, "messages per account")
	big := flag.Int("big", 100000, "messages in big@t1.example.com INBOX")
	workers := flag.Int("workers", 8, "accounts filled in parallel (one goroutine per account)")
	flag.Parse()

	ctx := context.Background()
	st, err := runtime.OpenMailStack(ctx, *cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer st.Close()

	type job struct {
		id uint32
		n  int
	}
	var jobs []job
	for t := 1; t <= *tenants; t++ {
		ten, err := st.Dir.CreateTenant(ctx, fmt.Sprintf("tenant %d", t), fmt.Sprintf("ext-%d", t), 0)
		must(err)
		dom, err := st.Dir.CreateDomain(ctx, ten.ID, fmt.Sprintf("t%d.example.com", t))
		must(err)
		for a := 1; a <= *accounts; a++ {
			local, n := fmt.Sprintf("user%d", a), *per
			if t == 1 && a == 1 {
				local, n = "big", *big
			}
			acc, err := st.Dir.CreateAccount(ctx, dom.ID, local, "loadtest")
			must(err)
			must(st.Inbox.EnsureMailboxes(ctx, acc.ID))
			jobs = append(jobs, job{acc.ID, n})
		}
	}

	var total int
	for _, j := range jobs {
		total += j.n
	}
	fmt.Fprintf(os.Stderr, "accounts=%d messages=%d\n", len(jobs), total)

	var done atomic.Int64
	start := time.Now()
	go func() {
		for range time.Tick(10 * time.Second) {
			d := done.Load()
			fmt.Fprintf(os.Stderr, "%d/%d (%.0f msg/s)\n", d, total, float64(d)/time.Since(start).Seconds())
		}
	}()

	ch := make(chan job)
	var wg sync.WaitGroup
	for range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				rng := rand.New(rand.NewPCG(uint64(j.id), 1))
				for i := 1; i <= j.n; i++ {
					_, err := st.Inbox.Deliver(ctx, j.id, message(rng, j.id, i))
					must(err)
					done.Add(1)
				}
			}
		}()
	}
	for _, j := range jobs {
		ch <- j
	}
	close(ch)
	wg.Wait()
	el := time.Since(start)
	fmt.Fprintf(os.Stderr, "delivered %d in %v (%.0f msg/s)\n", total, el.Round(time.Second), float64(total)/el.Seconds())
}

// message builds a ~2-3 KB plain-text mail. Every 1000th has subject "Fattura <n>" and body word "zanzibar".
func message(rng *rand.Rand, acc uint32, i int) []byte {
	var b strings.Builder
	date := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * 15 * time.Minute)
	subject := sentence(rng, 3+rng.IntN(5))
	if i%1000 == 0 {
		subject = fmt.Sprintf("Fattura %d", i)
	}
	fmt.Fprintf(&b, "From: sender%d <sender%d@example.org>\r\n", rng.IntN(200), rng.IntN(200))
	fmt.Fprintf(&b, "To: user <a%d@example.com>\r\n", acc)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", date.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%d.%d@load.example.org>\r\n", acc, i)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	for range 20 + rng.IntN(20) {
		b.WriteString(sentence(rng, 12))
		b.WriteString("\r\n")
	}
	if i%1000 == 0 {
		b.WriteString("zanzibar\r\n")
	}
	return []byte(b.String())
}

func sentence(rng *rand.Rand, n int) string {
	w := make([]string, n)
	for i := range w {
		w[i] = words[rng.IntN(len(words))]
	}
	return strings.Join(w, " ")
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
