package snapshot

import (
	"os"
	"path/filepath"
	"strings"
)

// Store is the runs directory: one subdirectory per host holding every
// sweep by timestamp, plus latest.json and baseline.json.
type Store string

func (st Store) Dir(host string) string {
	safe := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == ' ' {
			return '_'
		}
		return r
	}, host)
	return filepath.Join(string(st), safe)
}

func (st Store) path(host, which string) string {
	return filepath.Join(st.Dir(host), which+".json")
}

func (st Store) Latest(host string) (*Snapshot, error)   { return Load(st.path(host, "latest")) }
func (st Store) Baseline(host string) (*Snapshot, error) { return Load(st.path(host, "baseline")) }

// Resolve treats arg as a snapshot file when it ends in .json, otherwise
// as a host name whose latest or baseline sweep is wanted.
func (st Store) Resolve(arg, which string) (*Snapshot, error) {
	if strings.HasSuffix(arg, ".json") {
		return Load(arg)
	}
	return Load(st.path(arg, which))
}

// Save records a fresh sweep as both a timestamped file and latest.json,
// and as the baseline too when asked.
func (st Store) Save(host string, s *Snapshot, asBaseline bool) error {
	dir := st.Dir(host)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ts := s.Time.Format("20060102T150405Z")
	if err := Write(filepath.Join(dir, ts+".json"), s); err != nil {
		return err
	}
	if err := Write(st.path(host, "latest"), s); err != nil {
		return err
	}
	if asBaseline {
		return Write(st.path(host, "baseline"), s)
	}
	return nil
}

// Promote makes the latest sweep of host its baseline.
func (st Store) Promote(host string) (*Snapshot, error) {
	s, err := st.Latest(host)
	if err != nil {
		return nil, err
	}
	return s, Write(st.path(host, "baseline"), s)
}
