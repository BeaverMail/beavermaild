package directory

import (
	"path/filepath"
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
