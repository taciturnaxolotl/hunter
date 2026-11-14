package target

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/taciturnaxolotl/hunter/internal/snapshot"
)

func TestStepsMergeByFileAndProcess(t *testing.T) {
	obs := []snapshot.Obs{
		{Check: "fs", Key: "unowned:/usr/sbin/rt-tagd", Sev: snapshot.Warn},
		{Check: "ioc", Key: "path:/usr/sbin/rt-tagd", Sev: snapshot.Crit},
		{Check: "procs", Key: "pid:89:rt-tagd", Sev: snapshot.Crit, Detail: "pid=89 ppid=1 uid=0 comm=rt-tagd exe=/usr/sbin/rt-tagd cmd=/usr/sbin/rt-tagd"},
		{Check: "procs", Key: "pid:94:sleep", Sev: snapshot.Crit, Detail: "pid=94 ppid=1 uid=0 comm=sleep exe=/tmp/.x (deleted) cmd=/tmp/.x"},
		{Check: "cron", Key: "line:/etc/cron.d/sysupd:3870fb2d", Sev: snapshot.Crit},
		{Check: "net", Key: "conn:tcp/10.0.0.1:4444", Sev: snapshot.Crit},
	}
	steps := Steps(obs)
	if len(steps) != 4 {
		t.Fatalf("want 4 steps, got %d: %+v", len(steps), steps)
	}
	rt := steps[0]
	if rt.Path != "/usr/sbin/rt-tagd" || len(rt.Obs) != 3 || len(rt.Procs) != 1 || rt.Procs[0].Comm != "rt-tagd" {
		t.Errorf("rt-tagd findings should merge into one step: %+v", rt)
	}
	if steps[1].Path != "" || steps[1].Procs[0].PID != 94 {
		t.Errorf("a deleted exe leaves only the process to act on: %+v", steps[1])
	}
	if steps[2].Path != "/etc/cron.d/sysupd" {
		t.Errorf("cron line should point at its file: %+v", steps[2])
	}
	if steps[3].Path != "" || len(steps[3].Procs) != 0 || steps[3].Obs[0].Check != "net" {
		t.Errorf("a finding with no target is still a step: %+v", steps[3])
	}
	if got := AllowKey(obs[2]); got != "pid:*:rt-tagd" {
		t.Errorf("AllowKey = %q", got)
	}
}

func TestWhyNotQuarantine(t *testing.T) {
	dir := t.TempDir()
	implant := filepath.Join(dir, "implant")
	os.WriteFile(implant, []byte("x"), 0o755)
	for path, blocked := range map[string]bool{
		"/etc/shadow":                 true,
		"/etc/pam.d/sshd":             true,
		"/root/.bashrc":               true,
		"/proc/1/exe":                 true,
		implant:                       false,
		filepath.Join(dir, "missing"): true,
	} {
		if got := WhyNotQuarantine(path, nil) != ""; got != blocked {
			t.Errorf("%s: blocked=%v want %v", path, got, blocked)
		}
	}
	if WhyNotQuarantine(implant, func(string) bool { return true }) == "" {
		t.Error("package-owned files should be reinstalled, not quarantined")
	}
}
