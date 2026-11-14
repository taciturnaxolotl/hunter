//go:build linux

package target

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"github.com/taciturnaxolotl/hunter/rules"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type pwEnt struct {
	Name, Home, Shell string
	UID, GID          int
}

type collector struct {
	obs    []snapshot.Obs
	seen   map[string]int
	errs   []string
	now    time.Time
	since  time.Duration
	rules  *rules.Rules
	res    dirResolver
	owned  map[string]bool
	pkgMgr string
	passwd []pwEnt
	self   string
	selfP  int
	opts   Options
}

func (c *collector) add(check, key string, sev snapshot.Sev, msg, detail, hash string) {
	o := snapshot.Obs{Check: check, Key: key, Sev: sev, Msg: msg, Detail: detail, Hash: hash}
	id := o.ID()
	if i, ok := c.seen[id]; ok {
		// Same thing reported twice: keep the louder one.
		if sev > c.obs[i].Sev {
			c.obs[i] = o
		}
		return
	}
	c.seen[id] = len(c.obs)
	c.obs = append(c.obs, o)
}

func (c *collector) errf(format string, a ...any) {
	c.errs = append(c.errs, fmt.Sprintf(format, a...))
}

func (c *collector) isOwned(p string) bool {
	if c.owned == nil {
		return true
	}
	return c.owned[p] || c.owned[c.res.norm(p)]
}

func (c *collector) homes() []string {
	seen := map[string]bool{"/root": true}
	out := []string{"/root"}
	for _, e := range c.passwd {
		if e.Home == "" || e.Home == "/" || seen[e.Home] {
			continue
		}
		if fi, err := os.Stat(e.Home); err == nil && fi.IsDir() {
			seen[e.Home] = true
			out = append(out, e.Home)
		}
	}
	for _, h := range globAll("/home/*") {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func runCmd(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return out, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return out, err
}

func parsePasswd() []pwEnt {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	var out []pwEnt
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || strings.HasPrefix(line, "#") {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		out = append(out, pwEnt{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]})
	}
	return out
}

func osRelease() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
		}
	}
	return "unknown"
}

// loadOwnership builds the set of every file some package claims, read
// straight from the package databases where possible.
func (c *collector) loadOwnership() {
	owned := map[string]bool{}
	addLine := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || p[0] != '/' {
			return
		}
		owned[p] = true
		owned[c.res.norm(p)] = true
	}
	switch {
	case exists("/var/lib/dpkg/info"):
		c.pkgMgr = "dpkg"
		for _, f := range globAll("/var/lib/dpkg/info/*.list") {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, l := range strings.Split(string(b), "\n") {
				addLine(l)
			}
		}
	case exists("/var/lib/pacman/local"):
		c.pkgMgr = "pacman"
		for _, f := range globAll("/var/lib/pacman/local/*/files") {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			in := false
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(l, "%") {
					in = l == "%FILES%"
					continue
				}
				if in && l != "" {
					addLine("/" + strings.TrimSuffix(l, "/"))
				}
			}
		}
	case exists("/var/lib/rpm") || exists("/usr/lib/sysimage/rpm"):
		c.pkgMgr = "rpm"
		out, err := runCmd(90*time.Second, "rpm", "-qa", "--qf", "[%{FILENAMES}\n]")
		if err != nil {
			c.errf("rpm file list: %v", err)
			return
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			addLine(sc.Text())
		}
	case exists("/nix/store"):
		c.pkgMgr = "nix"
		return
	default:
		c.pkgMgr = "none"
		return
	}
	if len(owned) > 1000 {
		c.owned = owned
	} else {
		c.errf("package file list looked empty (%d entries); ownership checks disabled", len(owned))
	}
}

// Collect runs every check against the live system and returns what it saw.
func Collect(opts Options) (*snapshot.Snapshot, error) {
	start := time.Now()
	c := &collector{
		seen:  map[string]int{},
		now:   start,
		since: opts.Since,
		res:   dirResolver{},
		selfP: os.Getpid(),
		opts:  opts,
	}
	c.self, _ = os.Executable()
	pack, err := rules.Load(opts.Rules)
	if err != nil {
		return nil, err
	}
	c.rules = pack
	c.passwd = parsePasswd()

	c.loadOwnership()

	checks := []struct {
		name string
		fn   func()
	}{
		{"accounts", c.checkAccounts},
		{"shells", c.checkShells},
		{"preload", c.checkPreload},
		{"pam", c.checkPAM},
		{"ssh", c.checkSSH},
		{"systemd", c.checkSystemd},
		{"cron", c.checkCron},
		{"init", c.checkInitFiles},
		{"procs", c.checkProcs},
		{"net", c.checkNet},
		{"kernel", c.checkKernel},
		{"logs", c.checkLogs},
		{"fs", c.checkFS},
		{"ioc", c.checkIOC},
		{"pkg", c.checkPkgVerify},
	}
	for _, ch := range checks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					c.errf("%s check panicked: %v", ch.name, r)
				}
			}()
			ch.fn()
		}()
	}

	host, _ := os.Hostname()
	kern, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	snap := &snapshot.Snapshot{
		Version:  opts.Version,
		Hostname: host,
		OS:       osRelease(),
		Kernel:   strings.TrimSpace(string(kern)),
		Arch:     runtime.GOARCH,
		Time:     start.UTC(),
		Since:    opts.Since.String(),
		PkgMgr:   c.pkgMgr,
		Elapsed:  time.Since(start).Round(100 * time.Millisecond).String(),
		Obs:      c.obs,
		Errors:   c.errs,
	}
	for i, o := range snap.Obs {
		if o.Sev > snapshot.Info && c.rules.Allowed(o.Key) {
			snap.Obs[i].Sev = snapshot.Info
			snap.Obs[i].Msg = "allowed: " + o.Msg
		}
	}
	snapshot.Sort(snap.Obs)
	return snap, nil
}

// --- package verification -------------------------------------------------

var criticalBins = map[string]bool{
	"sshd": true, "sshd-session": true, "sshd-auth": true, "ssh": true, "scp": true, "sftp": true,
	"ssh-keygen": true, "ssh-agent": true, "ssh-add": true, "ssh-keyscan": true,
	"ss": true, "netstat": true, "ps": true, "top": true, "ls": true, "find": true, "lsof": true,
	"login": true, "su": true, "sudo": true, "bash": true, "sh": true, "dash": true, "nologin": true,
	"false": true, "true": true, "chpasswd": true, "passwd": true, "useradd": true, "usermod": true,
	"who": true, "w": true, "last": true, "kill": true, "pkill": true, "pgrep": true, "systemctl": true,
	"crontab": true, "cron": true, "crond": true, "rpm": true, "dnf": true, "yum": true, "apt": true,
	"dpkg": true, "ip": true, "chroot": true, "mount": true, "setcap": true, "getcap": true,
	"chattr": true, "lsattr": true, "strings": true, "file": true, "unix_chkpwd": true,
}

func sensitiveConfig(path string) bool {
	for _, p := range []string{"/etc/pam.d/", "/etc/security/", "/etc/ssh/", "/etc/sudoers", "/etc/nsswitch.conf", "/etc/ld.so", "/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", "/etc/shells", "/etc/login.defs", "/etc/systemd/"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func pkgCritical(path string) bool {
	base := filepath.Base(path)
	if criticalBins[base] {
		return true
	}
	for _, p := range []string{"pam_", "libpam", "libnss_", "ld-linux", "libc.so", "libcrypt", "site.", "hashlib.", "hmac."} {
		if strings.HasPrefix(base, p) {
			return true
		}
	}
	return strings.Contains(path, "/security/") || strings.HasSuffix(path, ".service") || strings.HasSuffix(path, ".socket")
}

func (c *collector) checkPkgVerify() {
	if !c.opts.PkgVerify {
		return
	}
	var out []byte
	var err error
	t := c.opts.PkgTimeout
	switch c.pkgMgr {
	case "rpm":
		out, err = runCmd(t, "rpm", "-Va", "--nomtime")
		if len(out) == 0 && err != nil {
			out, err = runCmd(t, "rpm", "-Va")
		}
	case "dpkg":
		out, err = runCmd(t, "dpkg", "--verify")
	case "pacman":
		out, err = runCmd(t, "pacman", "-Qkk")
	default:
		return
	}
	if err != nil && len(out) == 0 {
		// rpm/dpkg exit non-zero whenever anything fails verification;
		// only an empty output is a real failure.
		if !strings.Contains(err.Error(), "exit status") {
			c.errf("%s verify: %v", c.pkgMgr, err)
			return
		}
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		path, attrs, conf, ok := parseVerifyLine(c.pkgMgr, line)
		if !ok {
			continue
		}
		n++
		key := "pkg:" + path
		switch {
		case conf && sensitiveConfig(path) && strings.ContainsAny(attrs, "5S"):
			c.add("pkg", key, snapshot.Warn, "security-relevant config differs from package (ours or theirs?)", attrs, attrs)
		case conf:
			c.add("pkg", key, snapshot.Info, "config file differs from package", attrs, attrs)
		case attrs == "missing":
			c.add("pkg", key, snapshot.Info, "packaged file missing", attrs, attrs)
		case strings.ContainsAny(attrs, "5S") || strings.Contains(attrs, "checksum") || strings.Contains(attrs, "Size"):
			sev := snapshot.Warn
			if pkgCritical(path) {
				sev = snapshot.Crit
			}
			c.add("pkg", key, sev, "file contents differ from package (trojaned?)", attrs+" sha256="+short(sha256File(path)), attrs)
		case strings.Contains(attrs, "M") || strings.Contains(attrs, "Permissions"):
			sev := snapshot.Warn
			msg := "permissions differ from package"
			if fi, err := os.Stat(path); err == nil {
				switch {
				case fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 && !fi.IsDir():
					sev, msg = snapshot.Crit, "setuid/setgid added to packaged file"
				case fi.IsDir() && fi.Mode().Perm()&0o002 == 0:
					sev, msg = snapshot.Info, "directory permissions differ from package"
				case fi.Mode().Perm()&0o002 != 0:
					sev, msg = snapshot.Crit, "packaged file made world-writable"
				}
			}
			c.add("pkg", key, sev, msg, attrs, attrs)
		default:
			c.add("pkg", key, snapshot.Info, "packaged file metadata differs", attrs, attrs)
		}
	}
	c.add("pkg", "verify:summary", snapshot.Info, fmt.Sprintf("%s verify reported %d files", c.pkgMgr, n), "", "")
}

func parseVerifyLine(pm, line string) (path, attrs string, conf, ok bool) {
	line = strings.TrimRight(line, "\r")
	if line == "" {
		return
	}
	if pm == "pacman" {
		// warning: pkg: /usr/bin/foo (SHA256 checksum mismatch)
		if !strings.HasPrefix(line, "warning: ") {
			return
		}
		rest := strings.TrimPrefix(line, "warning: ")
		i := strings.Index(rest, ": /")
		if i < 0 {
			return
		}
		rest = rest[i+2:]
		j := strings.LastIndex(rest, " (")
		if j < 0 {
			return
		}
		path, attrs = rest[:j], strings.TrimSuffix(rest[j+2:], ")")
		if strings.Contains(attrs, "No such file") {
			attrs = "missing"
		}
		conf = strings.HasPrefix(path, "/etc/")
		return path, attrs, conf, true
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		return
	}
	if f[0] != "missing" && len(f[0]) != 9 {
		return
	}
	last := f[len(f)-1]
	if !strings.HasPrefix(last, "/") {
		return
	}
	attrs = f[0]
	if len(f) >= 3 && len(f[1]) == 1 && f[1] == "c" {
		conf = true
	}
	return last, attrs, conf, true
}
