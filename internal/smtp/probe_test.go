package smtp

import (
	"context"
	"testing"
)

func TestProbeRelayOK(t *testing.T) {
	t.Parallel()
	m := startMockMX(t, mxScript{})
	defer m.close()

	res := ProbeRemote(context.Background(), RemoteConfig{Relay: m.addr}, ProbeRequest{Mode: "relay"})
	if !res.OK {
		t.Fatalf("probe %#v", res)
	}
	if res.Mode != "relay" || res.Host != m.addr {
		t.Fatalf("mode/host %#v", res)
	}
	if !stepOK(res, "connect") || !stepOK(res, "ehlo") {
		t.Fatalf("steps %#v", res.Steps)
	}
}

func TestProbeMXRequiresTo(t *testing.T) {
	t.Parallel()
	res := ProbeRemote(context.Background(), RemoteConfig{}, ProbeRequest{Mode: "mx"})
	if res.OK {
		t.Fatal("expected failure")
	}
	if !stepHasError(res, "domain") {
		t.Fatalf("steps %#v", res.Steps)
	}
}

func TestProbeMXLookupTimeout(t *testing.T) {
	t.Parallel()
	// Context already expired: LookupHosts must fail fast, not hang.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := ProbeRemote(ctx, RemoteConfig{}, ProbeRequest{Mode: "mx", To: "example.com"})
	if res.OK {
		t.Fatal("expected failure on canceled context")
	}
	if !stepHasError(res, "mx_lookup") && !stepHasError(res, "connect") {
		t.Fatalf("want mx_lookup or connect error, steps %#v", res.Steps)
	}
}

func stepOK(res ProbeResult, name string) bool {
	for _, s := range res.Steps {
		if s.Name == name {
			return s.OK
		}
	}
	return false
}

func stepHasError(res ProbeResult, name string) bool {
	for _, s := range res.Steps {
		if s.Name == name && !s.OK {
			return true
		}
	}
	return false
}
