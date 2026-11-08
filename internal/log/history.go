package log

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// ReadHistory scans rotating JSON log files (path, path.1, …) newest-first.
// keep is the rotation count used by OpenFile (default 5).
func ReadHistory(path string, keep int, q Query) ([]Entry, error) {
	if path == "" {
		return nil, nil
	}
	if keep <= 0 {
		keep = defaultKeep
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	minLvl := slog.LevelInfo
	if q.LevelSet {
		minLvl = q.MinLevel
	}
	needle := strings.ToLower(strings.TrimSpace(q.Q))

	out := make([]Entry, 0, limit)
	for i := 0; i < keep && len(out) < limit; i++ {
		fp := path
		if i > 0 {
			fp = path + "." + strconv.Itoa(i)
		}
		if err := scanFileNewestFirst(fp, q.Before, minLvl, needle, &out, limit); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return out, err
		}
	}
	return out, nil
}

func scanFileNewestFirst(path string, before time.Time, minLvl slog.Level, needle string, out *[]Entry, limit int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var lines [][]byte
	sc := bufio.NewScanner(f)
	// ponytail: 1 MiB max line; ops JSON lines are small
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		lines = append(lines, cp)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	for i := len(lines) - 1; i >= 0 && len(*out) < limit; i-- {
		var e Entry
		if err := json.Unmarshal(lines[i], &e); err != nil {
			continue
		}
		if !before.IsZero() && !e.Time.Before(before) {
			continue
		}
		if parseLevel(e.Level) < minLvl {
			continue
		}
		if needle != "" && !entryMatch(e, needle) {
			continue
		}
		*out = append(*out, e)
	}
	return nil
}
