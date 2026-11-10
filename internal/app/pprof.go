// Opt-in profiler for diagnosing load problems (BEAVER_PPROF=127.0.0.1:6060).
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"time"
)

// startPprof serves net/http/pprof on the loopback address in BEAVER_PPROF, with block and mutex
// profiling on. Off unless set: profiles expose stacks and memory, and profiling costs CPU.
func startPprof(ctx context.Context, log *slog.Logger) error {
	addr := os.Getenv("BEAVER_PPROF")
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("BEAVER_PPROF %q: want a loopback host:port such as 127.0.0.1:6060", addr)
	}
	runtime.SetBlockProfileRate(int(time.Millisecond)) // waits of 1 ms or more
	runtime.SetMutexProfileFraction(10)
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("pprof listen: %w", err)
	}
	log.Warn("pprof enabled: profiling endpoints on loopback", "addr", ln.Addr().String())
	go func() { _ = srv.Serve(ln) }()
	go func() { <-ctx.Done(); _ = srv.Close() }()
	return nil
}
