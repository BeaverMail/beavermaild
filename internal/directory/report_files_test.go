package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The same message delivered to both report addresses (dmarc-reports@ and
// tls-reports@) in the same instant must get distinct file names: Meta.File is the
// report list key across kinds, duplicates break keyed UI rendering.
func TestSaveDomainReportFileUniqueAcrossKinds(t *testing.T) {
	dataDir := t.TempDir()
	raw := []byte("Subject: report\r\n\r\nbody")
	p1, err := SaveDomainReport(dataDir, 7, "dmarc", "a@b.test", "dmarc-reports@x.test", raw)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := SaveDomainReport(dataDir, 7, "tls", "a@b.test", "tls-reports@x.test", raw)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p1) == filepath.Base(p2) {
		t.Fatalf("same basename across kinds: %s", filepath.Base(p1))
	}
	stored, err := ListDomainReports(dataDir, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 {
		t.Fatalf("want 2 stored reports, got %d", len(stored))
	}
	seen := map[string]bool{}
	for _, st := range stored {
		if seen[st.Meta.File] {
			t.Fatalf("duplicate Meta.File %q", st.Meta.File)
		}
		seen[st.Meta.File] = true
	}
}

// R2 (RFC 9990 8.2): the store keeps the newest maxReportsPerKind reports of a kind; the oldest go.
// Before, every message to dmarc-reports@ stayed on disk forever.
func TestSaveDomainReportPrunesOldest(t *testing.T) {
	dataDir := t.TempDir()
	dir := filepath.Join(DomainDir(dataDir, 7), "reports", "dmarc")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range maxReportsPerKind {
		base := fmt.Sprintf("dmarc-20200101T%06dZ-0000", i)
		for _, ext := range []string{".eml", ".json"} {
			if err := os.WriteFile(filepath.Join(dir, base+ext), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	p, err := SaveDomainReport(dataDir, 7, "dmarc", "a@b.test", "dmarc-reports@x.test", []byte("Subject: r\r\n\r\nbody"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"dmarc-20200101T000000Z-0000.eml", "dmarc-20200101T000000Z-0000.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Fatalf("oldest %s kept: %v", f, err)
		}
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("new report pruned: %v", err)
	}
	if n, _ := filepath.Glob(filepath.Join(dir, "*.eml")); len(n) != maxReportsPerKind {
		t.Fatalf("%d reports kept, want %d", len(n), maxReportsPerKind)
	}
}

// The byte bound drops old reports too, but never the one just saved.
func TestPruneReportsByteBound(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, 600)
	for _, name := range []string{"dmarc-1.eml", "dmarc-2.eml", "dmarc-3.eml"} {
		if err := os.WriteFile(filepath.Join(dir, name), big, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneReports(dir, 10, 1000); err != nil {
		t.Fatal(err)
	}
	if n, _ := filepath.Glob(filepath.Join(dir, "*.eml")); len(n) != 1 || filepath.Base(n[0]) != "dmarc-3.eml" {
		t.Fatalf("kept %v", n)
	}
}

// Review S3: a stored report is parsed once; listings read the cache beside it, pruning removes it.
// Before, every listing decompressed every stored report again.
func TestParseStoredReportCache(t *testing.T) {
	dataDir := t.TempDir()
	path, err := SaveDomainReport(dataDir, 7, "dmarc", "a@b.test", "dmarc-reports@x.test", []byte("Subject: r\r\n\r\nnot a report"))
	if err != nil {
		t.Fatal(err)
	}
	first := ParseStoredReport(nil, "dmarc", path)
	cache := strings.TrimSuffix(path, ".eml") + ".parsed.json"
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("no cache: %v", err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if again := ParseStoredReport(nil, "dmarc", path); !reflect.DeepEqual(again, first) {
		t.Fatalf("cache not used: %+v vs %+v", again, first)
	}
	if err := pruneReports(filepath.Dir(path), 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("cache kept after prune: %v", err)
	}
}
