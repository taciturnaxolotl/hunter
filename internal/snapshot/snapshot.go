// Package snapshot is the data model shared by both halves of hunter: the
// observations a target collects, and the diff the laptop computes between
// two sweeps of the same host.
package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Sev is how much a finding should worry a human. Info observations are
// not findings on their own; they exist so a later sweep can diff against
// them (a new unit file, a new listener, a changed authorized_keys).
type Sev int

const (
	Info Sev = iota
	Warn
	Crit
)

func (s Sev) String() string {
	switch s {
	case Crit:
		return "crit"
	case Warn:
		return "warn"
	default:
		return "info"
	}
}

func ParseSev(s string) (Sev, error) {
	switch strings.ToLower(s) {
	case "crit", "critical":
		return Crit, nil
	case "warn", "warning":
		return Warn, nil
	case "info", "":
		return Info, nil
	}
	return Info, fmt.Errorf("unknown severity %q", s)
}

func (s Sev) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Sev) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	v, err := ParseSev(str)
	*s = v
	return err
}

// Obs is one observation. Check+Key identify it across sweeps; Hash (or
// Detail when Hash is empty) decides whether it changed.
type Obs struct {
	Check  string `json:"check"`
	Key    string `json:"key"`
	Sev    Sev    `json:"sev"`
	Msg    string `json:"msg"`
	Detail string `json:"detail,omitempty"`
	Hash   string `json:"hash,omitempty"`
}

func (o Obs) ID() string { return o.Check + "\x00" + o.Key }

func (o Obs) fingerprint() string {
	if o.Hash != "" {
		return o.Hash
	}
	return o.Sev.String() + "|" + o.Msg + "|" + o.Detail
}

type Snapshot struct {
	Version  string    `json:"version"`
	Hostname string    `json:"hostname"`
	OS       string    `json:"os"`
	Kernel   string    `json:"kernel"`
	Arch     string    `json:"arch"`
	Time     time.Time `json:"time"`
	Since    string    `json:"since"`
	PkgMgr   string    `json:"pkgmgr"`
	Elapsed  string    `json:"elapsed"`
	Obs      []Obs     `json:"obs"`
	Errors   []string  `json:"errors,omitempty"`
}

// Counts tallies observations by severity.
func (s *Snapshot) Counts() (crit, warn, info int) {
	for _, o := range s.Obs {
		switch o.Sev {
		case Crit:
			crit++
		case Warn:
			warn++
		default:
			info++
		}
	}
	return
}

// Filter returns the observations at or above min, optionally limited to
// one check, sorted loudest first.
func (s *Snapshot) Filter(min Sev, check string) []Obs {
	var out []Obs
	for _, o := range s.Obs {
		if o.Sev >= min && (check == "" || o.Check == check) {
			out = append(out, o)
		}
	}
	Sort(out)
	return out
}

func Load(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

func Write(path string, s *Snapshot) error {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

type Kind string

const (
	New     Kind = "new"
	Changed Kind = "changed"
	Gone    Kind = "gone"
)

type Change struct {
	Kind Kind `json:"kind"`
	Obs  Obs  `json:"obs"`
	Old  *Obs `json:"old,omitempty"`
}

// Diff lists what changed from base to cur: new and changed observations
// loudest first, then everything that disappeared.
func Diff(base, cur *Snapshot) []Change {
	old := make(map[string]Obs, len(base.Obs))
	for _, o := range base.Obs {
		old[o.ID()] = o
	}
	var out []Change
	seen := make(map[string]bool, len(cur.Obs))
	for _, o := range cur.Obs {
		seen[o.ID()] = true
		prev, ok := old[o.ID()]
		switch {
		case !ok:
			out = append(out, Change{Kind: New, Obs: o})
		case prev.fingerprint() != o.fingerprint():
			out = append(out, Change{Kind: Changed, Obs: o, Old: &prev})
		}
	}
	for _, o := range base.Obs {
		if !seen[o.ID()] {
			out = append(out, Change{Kind: Gone, Obs: o})
		}
	}
	kindRank := map[Kind]int{New: 0, Changed: 1, Gone: 2}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Kind == Gone) != (b.Kind == Gone) {
			return b.Kind == Gone
		}
		if a.Obs.Sev != b.Obs.Sev {
			return a.Obs.Sev > b.Obs.Sev
		}
		if kindRank[a.Kind] != kindRank[b.Kind] {
			return kindRank[a.Kind] < kindRank[b.Kind]
		}
		return a.Obs.ID() < b.Obs.ID()
	})
	return out
}

// Sort orders observations loudest first, then by identity.
func Sort(obs []Obs) {
	sort.SliceStable(obs, func(i, j int) bool {
		if obs[i].Sev != obs[j].Sev {
			return obs[i].Sev > obs[j].Sev
		}
		return obs[i].ID() < obs[j].ID()
	})
}
