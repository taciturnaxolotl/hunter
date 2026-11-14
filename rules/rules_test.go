package rules

import (
	"strings"
	"testing"
)

func TestLoadMergesExtraPacks(t *testing.T) {
	r, err := Load([]string{`{"name":"extra","paths":["/opt/evil"]}`})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Name, "extra") || r.Paths[len(r.Paths)-1] != "/opt/evil" || len(r.PubKeys) == 0 {
		t.Fatalf("merge failed: %+v", r.Name)
	}
}

func TestAllowed(t *testing.T) {
	r, err := Load([]string{`{"name":"allow","allow":["mod:spelunk","pid:*:scoringd"]}`})
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]bool{
		"mod:spelunk":       true,
		"pid:812:scoringd":  true,
		"mod:spelunk2":      false,
		"pid:812:rt-tagd":   false,
		"path:/usr/sbin/rt": false,
	} {
		if got := r.Allowed(key); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", key, got, want)
		}
	}
}
