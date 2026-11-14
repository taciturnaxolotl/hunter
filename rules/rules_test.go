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
