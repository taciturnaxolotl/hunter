package snapshot

import "testing"

func TestDiff(t *testing.T) {
	base := &Snapshot{Obs: []Obs{
		{Check: "ssh", Key: "ak:a", Sev: Info, Msg: "authorized key", Detail: "kieran"},
		{Check: "cron", Key: "file:/etc/crontab", Sev: Info, Hash: "aaa"},
		{Check: "net", Key: "listen:tcp/22", Sev: Info, Hash: "sshd"},
	}}
	cur := &Snapshot{Obs: []Obs{
		{Check: "ssh", Key: "ak:a", Sev: Info, Msg: "authorized key", Detail: "kieran"},
		{Check: "cron", Key: "file:/etc/crontab", Sev: Info, Hash: "bbb"},
		{Check: "fs", Key: "suid:/tmp/x", Sev: Crit, Msg: "setuid file in a user/temp dir"},
	}}
	ch := Diff(base, cur)
	if len(ch) != 3 {
		t.Fatalf("want 3 changes, got %d: %+v", len(ch), ch)
	}
	if ch[0].Kind != New || ch[0].Obs.Sev != Crit {
		t.Errorf("crit new change should sort first, got %+v", ch[0])
	}
	if ch[1].Kind != Changed || ch[1].Old == nil || ch[1].Old.Hash != "aaa" {
		t.Errorf("crontab should be changed, got %+v", ch[1])
	}
	if ch[2].Kind != Gone {
		t.Errorf("listener should be gone last, got %+v", ch[2])
	}
}

func TestStoreRoundTrip(t *testing.T) {
	st := Store(t.TempDir())
	s := &Snapshot{Hostname: "web", Obs: []Obs{{Check: "fs", Key: "k", Sev: Warn}}}
	if err := st.Save("root@10.0.0.1:22", s, true); err != nil {
		t.Fatal(err)
	}
	got, err := st.Resolve("root@10.0.0.1:22", "baseline")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "web" || got.Obs[0].Sev != Warn {
		t.Fatalf("round trip lost data: %+v", got)
	}
}
