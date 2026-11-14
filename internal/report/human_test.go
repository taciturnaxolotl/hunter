package report

import (
	"strings"
	"testing"

	"github.com/taciturnaxolotl/hunter/internal/snapshot"
)

func TestRenderFindingsGroupsByCheckWithoutPadding(t *testing.T) {
	obs := []snapshot.Obs{
		{Check: "ssh", Key: "ak:x", Sev: snapshot.Crit, Msg: "red team master key", Detail: "ssh-ed25519 updater@acme"},
		{Check: "fs", Key: "suid:/usr/bin/find", Sev: snapshot.Crit, Msg: "setuid GTFOBin"},
		{Check: "ssh", Key: "ak:y", Sev: snapshot.Warn, Msg: "new authorized key"},
	}
	out := RenderFindings(obs, 0)
	if strings.Count(out, "ssh") < 1 || strings.Index(out, "ssh 2") > strings.Index(out, "fs 1") {
		t.Fatalf("ssh group should come first with both findings:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasSuffix(line, " ") {
			t.Fatalf("trailing padding on %q", line)
		}
	}
	if !strings.Contains(RenderFindings(obs, 1), "2 more findings") {
		t.Fatal("max should truncate")
	}
}
