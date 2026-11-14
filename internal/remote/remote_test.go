package remote

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseHost(t *testing.T) {
	cases := map[string]Host{
		"192.168.3.5":         {User: "root", Addr: "192.168.3.5", Name: "192.168.3.5"},
		"blueteam@10.0.0.2":   {User: "blueteam", Addr: "10.0.0.2", Name: "10.0.0.2"},
		"root@127.0.0.1:2222": {User: "root", Addr: "127.0.0.1", Port: "2222", Name: "127.0.0.1_2222"},
	}
	for in, want := range cases {
		if got := ParseHost(in, "", "root"); got != want {
			t.Errorf("%s: got %+v want %+v", in, got, want)
		}
	}
}

func TestReadHosts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hosts.txt")
	os.WriteFile(p, []byte("# team 3\n10.0.0.5 web\n\nadmin@10.0.0.6:2222  # db box\n"), 0o600)
	hs, err := ReadHosts(p, "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != 2 || hs[0].Name != "web" || hs[1].User != "admin" || hs[1].Port != "2222" {
		t.Fatalf("got %+v", hs)
	}
}
