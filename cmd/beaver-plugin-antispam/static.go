// Static deny lists for beaver-plugin-antispam.
package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type staticLists struct {
	mu      sync.RWMutex
	denyIP  []net.IP
	denyCIDR []*net.IPNet
	denyFrom []string
	denyRcpt []string
}

func newStaticLists(dataDir string) *staticLists {
	s := &staticLists{}
	s.reload(defaultConfig(), dataDir)
	return s
}

func (s *staticLists) reload(cfg pluginConfig, dataDir string) {
	base := antispamDir(dataDir)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denyIP = nil
	s.denyCIDR = nil
	s.denyFrom = loadListFiles(base, cfg.Static.DenyMailFrom)
	s.denyRcpt = loadListFiles(base, cfg.Static.DenyRcptTo)
	for _, entry := range loadListFiles(base, cfg.Static.DenyClientIP) {
		if strings.Contains(entry, "/") {
			if _, n, err := net.ParseCIDR(entry); err == nil {
				s.denyCIDR = append(s.denyCIDR, n)
				continue
			}
		}
		if ip := net.ParseIP(entry); ip != nil {
			s.denyIP = append(s.denyIP, ip)
		}
	}
}

func loadListFiles(base string, names []string) []string {
	var out []string
	for _, name := range names {
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(base, name)
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			out = append(out, strings.ToLower(line))
		}
		_ = f.Close()
	}
	return out
}

func (s *staticLists) deniesIP(clientIP string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, deny := range s.denyIP {
		if deny.Equal(ip) {
			return true
		}
	}
	for _, n := range s.denyCIDR {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *staticLists) deniesFrom(addr string) bool {
	addr = strings.ToLower(strings.TrimSpace(addr))
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rule := range s.denyFrom {
		if matchAddrRule(addr, rule) {
			return true
		}
	}
	return false
}

func (s *staticLists) deniesRcpt(addr string) bool {
	addr = strings.ToLower(strings.TrimSpace(addr))
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rule := range s.denyRcpt {
		if matchAddrRule(addr, rule) {
			return true
		}
	}
	return false
}

func matchAddrRule(addr, rule string) bool {
	if strings.HasPrefix(rule, "@") {
		dom := strings.TrimPrefix(rule, "@")
		i := strings.LastIndexByte(addr, '@')
		if i < 0 {
			return false
		}
		return addr[i+1:] == dom || strings.HasSuffix(addr[i+1:], "."+dom)
	}
	return addr == rule
}
