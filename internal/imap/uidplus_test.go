package imap

import "testing"

func TestFormatUIDSet(t *testing.T) {
	t.Parallel()

	if got := formatUIDSet([]uint32{3, 1, 2}); got != "1:3" {
		t.Fatalf("range %q", got)
	}
	if got := formatUIDSet([]uint32{1, 3, 5}); got != "1,3,5" {
		t.Fatalf("list %q", got)
	}
	if formatAppendUID(42, 7) != "APPENDUID 42 7" {
		t.Fatal("appenduid")
	}
	if formatCopyUID(9, []uint32{1}, []uint32{2}) != "COPYUID 9 1 2" {
		t.Fatal("copyuid")
	}
}
