// IMAP UIDPLUS response codes (RFC 4315).
package imap

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// formatAppendUID builds APPENDUID validity uid for a tagged OK response.
func formatAppendUID(uidValidity, uid uint32) string {
	return fmt.Sprintf("APPENDUID %d %d", uidValidity, uid)
}

// formatCopyUID builds COPYUID validity src-set dest-set for a tagged OK response.
func formatCopyUID(uidValidity uint32, srcUIDs, destUIDs []uint32) string {
	return fmt.Sprintf("COPYUID %d %s %s", uidValidity, formatUIDSet(srcUIDs), formatUIDSet(destUIDs))
}

// formatUIDSet renders UIDs in IMAP sequence-set form (e.g. 1,3:5).
func formatUIDSet(uids []uint32) string {
	if len(uids) == 0 {
		return ""
	}
	sorted := append([]uint32(nil), uids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var parts []string
	start, end := sorted[0], sorted[0]
	flush := func() {
		if start == end {
			parts = append(parts, strconv.FormatUint(uint64(start), 10))
		} else {
			parts = append(parts, fmt.Sprintf("%d:%d", start, end))
		}
	}
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == end+1 {
			end = sorted[i]
			continue
		}
		flush()
		start, end = sorted[i], sorted[i]
	}
	flush()
	return strings.Join(parts, ",")
}
