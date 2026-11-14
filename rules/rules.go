// Package rules holds indicator packs: exact things a known red team kit
// leaves behind. Structural checks live in Go; anything competition
// specific (paths, strings, keys, hashes, C2 addresses) belongs in a pack
// so it can be extended mid-competition without a rebuild.
package rules

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path"
)

// Rules is one pack, or several merged.
type Rules struct {
	Name    string   `json:"name"`
	Source  string   `json:"source,omitempty"`
	Paths   []string `json:"paths,omitempty"`   // globs; existing = crit
	Strings []string `json:"strings,omitempty"` // searched in config/temp/home dirs
	Shadow  []string `json:"shadow,omitempty"`  // substrings of a shadow hash field
	PubKeys []string `json:"pubkeys,omitempty"` // base64 key blobs
	IPs     []string `json:"ips,omitempty"`     // remote addresses
	Procs   []string `json:"procs,omitempty"`   // process names (comm or argv0 basename)
	Users   []string `json:"users,omitempty"`   // account names
	// Allow lists observation keys (globs, e.g. "mod:spelunk" or
	// "pid:*:scoringd") known to be legitimate on this network. They stay
	// in the snapshot as info, so a change to them still shows in a diff.
	Allow []string `json:"allow,omitempty"`
	Files []struct {
		Glob     string   `json:"glob"`
		Contains []string `json:"contains"`
	} `json:"file_contains,omitempty"`
}

//go:embed ccdc-kit.json
var builtin []byte

// Load merges the builtin pack with extra packs given as raw JSON
// (the driver ships them inline so the target needs no files).
func Load(extra []string) (*Rules, error) {
	var all Rules
	if err := json.Unmarshal(builtin, &all); err != nil {
		return nil, fmt.Errorf("builtin rules: %w", err)
	}
	for i, raw := range extra {
		var r Rules
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, fmt.Errorf("extra rules #%d: %w", i+1, err)
		}
		all.Name += "+" + r.Name
		all.Paths = append(all.Paths, r.Paths...)
		all.Strings = append(all.Strings, r.Strings...)
		all.Shadow = append(all.Shadow, r.Shadow...)
		all.PubKeys = append(all.PubKeys, r.PubKeys...)
		all.IPs = append(all.IPs, r.IPs...)
		all.Procs = append(all.Procs, r.Procs...)
		all.Users = append(all.Users, r.Users...)
		all.Files = append(all.Files, r.Files...)
		all.Allow = append(all.Allow, r.Allow...)
	}
	return &all, nil
}

// Allowed reports whether an observation key is on the allow list.
func (r *Rules) Allowed(key string) bool {
	for _, pat := range r.Allow {
		if pat == key {
			return true
		}
		if ok, _ := path.Match(pat, key); ok {
			return true
		}
	}
	return false
}
