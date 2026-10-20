package main

import (
	"context"
	"net"
	"testing"
)

func fakeRBL(reply net.IP, seen *[]string) *rblChecker {
	c := newRBLChecker()
	c.lookupIP = func(_ context.Context, _, host string) ([]net.IP, error) {
		if seen != nil {
			*seen = append(*seen, host)
		}
		return []net.IP{reply}, nil
	}
	return c
}

// Only the configured return codes count as a listing (defaults mirror Spamhaus usage).
func TestRBLZoneCodes(t *testing.T) {
	cfg := defaultConfig().RBL
	cfg.Enabled = true
	for _, tc := range []struct {
		zone   string
		reply  net.IP
		listed bool
	}{
		{"dbl.spamhaus.org", net.IPv4(127, 0, 1, 2), true},
		{"dbl.spamhaus.org", net.IPv4(127, 0, 1, 102), false}, // abused legit domain
		{"zrd.spamhaus.org", net.IPv4(127, 0, 2, 10), true},
		{"zrd.spamhaus.org", net.IPv4(127, 0, 2, 30), false},
		{"zen.spamhaus.org", net.IPv4(127, 0, 0, 11), true}, // PBL
		{"zen.spamhaus.org", net.IPv4(127, 0, 0, 8), false},
		{"other.example", net.IPv4(127, 0, 0, 8), true}, // no codes configured: any 127.x
	} {
		cfg.Zones = []string{tc.zone}
		listed, _, failed := fakeRBL(tc.reply, nil).checkDomain("example.com", cfg)
		if listed != tc.listed || failed {
			t.Fatalf("%s %s: listed=%v failed=%v want listed=%v", tc.zone, tc.reply, listed, failed, tc.listed)
		}
	}
}

// Submission clients (home/mobile IPs, often in PBL) are never rejected by IP RBL at connect.
func TestConnectRBLSkippedForSubmission(t *testing.T) {
	cfg := defaultConfig()
	cfg.RBL.Enabled = true
	cfg.RBL.ClientIPZones = []string{"zen.spamhaus.org"}
	e := &engine{static: newStaticLists(t.TempDir()), rbl: fakeRBL(net.IPv4(127, 0, 0, 11), nil), tags: map[string][]string{}}

	in := e.handleConnect(filterReq{ID: "1", ClientIP: "192.0.2.10", Listener: "inbound"}, cfg)
	if in.Action != "reject" {
		t.Fatalf("inbound listed IP: action=%q want reject", in.Action)
	}
	sub := e.handleConnect(filterReq{ID: "2", ClientIP: "192.0.2.10", Listener: "submission"}, cfg)
	if sub.Action != "accept" {
		t.Fatalf("submission: action=%q want accept", sub.Action)
	}
}

// Envelope sender and HELO domains are checked against domain zones for inbound mail only.
func TestDomainRBLChecksSenderAndHelo(t *testing.T) {
	cfg := defaultConfig()
	cfg.RBL.Enabled = true
	cfg.RBL.DomainZones = []string{"dbl.spamhaus.org"}
	var seen []string
	eng := &engine{rbl: fakeRBL(net.IPv4(127, 0, 1, 2), &seen)}

	ctx := &classifyCtx{req: filterReq{From: "a@mail.bad.example", EHLODomain: "mx.helo.example", Listener: "inbound"}, cfg: cfg, rblBudget: newRBLBudget(10)}
	var res classifyResult
	analyzeDomain(ctx, &res, eng)
	if len(seen) != 2 || seen[0] != "bad.example.dbl.spamhaus.org" || seen[1] != "helo.example.dbl.spamhaus.org" {
		t.Fatalf("queries %v", seen)
	}
	if !containsTag(res.tags, "RBL_DBL") {
		t.Fatalf("tags %v", res.tags)
	}

	seen = nil
	ctx.req.Listener = "submission"
	analyzeDomain(ctx, &classifyResult{}, eng)
	if len(seen) != 0 {
		t.Fatalf("submission must not query sender/HELO domains: %v", seen)
	}
}
