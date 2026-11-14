package target

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/taciturnaxolotl/hunter/internal/snapshot"
)

// Proc is a process a finding is about, as the snapshot saw it.
type Proc struct {
	PID  int
	Comm string
}

// Step is one thing the fix walkthrough can act on: a file or a set of
// processes, with every finding that points at it.
type Step struct {
	Path  string // file the findings are about, if any
	Procs []Proc
	Obs   []snapshot.Obs
}

// Sev is the loudest finding in the step.
func (s Step) Sev() snapshot.Sev {
	var max snapshot.Sev
	for _, o := range s.Obs {
		if o.Sev > max {
			max = o.Sev
		}
	}
	return max
}

func (s Step) actionable() bool { return s.Path != "" || len(s.Procs) > 0 }

// Steps turns findings into steps, merging findings about the same file
// or process, loudest first. A finding with no file or process (a
// connection, a kernel module) is a step of its own, which can still be
// allowed.
func Steps(obs []snapshot.Obs) []Step {
	var steps []*Step
	byKey := map[string]*Step{}
	for _, o := range obs {
		path, proc := target(o)
		key := path
		if key == "" && proc != nil {
			key = "pid:" + strconv.Itoa(proc.PID)
		}
		if key == "" {
			key = "obs:" + o.ID()
		}
		st, ok := byKey[key]
		if !ok {
			st = &Step{Path: path}
			byKey[key] = st
			steps = append(steps, st)
		}
		st.Obs = append(st.Obs, o)
		if proc != nil && !hasProc(st.Procs, proc.PID) {
			st.Procs = append(st.Procs, *proc)
		}
	}
	out := make([]Step, len(steps))
	for i, s := range steps {
		out[i] = *s
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := out[i].Sev(), out[j].Sev(); a != b {
			return a > b
		}
		return out[i].actionable() && !out[j].actionable()
	})
	return out
}

func hasProc(ps []Proc, pid int) bool {
	for _, p := range ps {
		if p.PID == pid {
			return true
		}
	}
	return false
}

// AllowKey is the allow-list pattern for an observation: its key, with
// the pid wildcarded so the entry survives a restart.
func AllowKey(o snapshot.Obs) string {
	for _, p := range []string{"", "env:", "cwd:"} {
		if rest, ok := strings.CutPrefix(o.Key, p+"pid:"); ok {
			if _, comm, ok := strings.Cut(rest, ":"); ok {
				return p + "pid:*:" + comm
			}
		}
	}
	return o.Key
}

// target reads which file or process an observation is about from its
// key ("suid:/usr/bin/find", "line:/etc/cron.d/x:abcd", "pid:89:rt-tagd").
func target(o snapshot.Obs) (path string, proc *Proc) {
	key := o.Key
	for _, p := range []string{"env:", "cwd:"} {
		key = strings.TrimPrefix(key, p)
	}
	if rest, ok := strings.CutPrefix(key, "pid:"); ok {
		pidS, comm, _ := strings.Cut(rest, ":")
		pid, err := strconv.Atoi(pidS)
		if err != nil {
			return "", nil
		}
		return detailField(o.Detail, "exe"), &Proc{PID: pid, Comm: comm}
	}
	_, rest, ok := strings.Cut(key, ":")
	if !ok || !strings.HasPrefix(rest, "/") {
		return "", nil
	}
	path, _, _ = strings.Cut(rest, ":")
	return path, nil
}

// detailField pulls exe=... out of a process detail; deleted and memfd
// executables have no file left to act on.
func detailField(detail, name string) string {
	_, v, ok := strings.Cut(detail, " "+name+"=")
	if !ok {
		return ""
	}
	v, _, _ = strings.Cut(v, " cmd=")
	if strings.HasSuffix(v, " (deleted)") || strings.HasPrefix(v, "/memfd:") || !strings.HasPrefix(v, "/") {
		return ""
	}
	return v
}

var protectedFiles = map[string]bool{
	"/etc/passwd": true, "/etc/shadow": true, "/etc/group": true, "/etc/gshadow": true,
	"/etc/sudoers": true, "/etc/nsswitch.conf": true, "/etc/hosts": true, "/etc/fstab": true,
	"/etc/shells": true, "/etc/crontab": true, "/etc/profile": true, "/etc/bashrc": true,
	"/etc/bash.bashrc": true, "/etc/login.defs": true, "/etc/ssh/sshd_config": true,
	"/etc/ld.so.conf": true, "/etc/resolv.conf": true, "/etc/environment": true,
}

// WhyNotQuarantine says why moving path away would do more harm than
// good, or "" when quarantine is a reasonable fix. owned reports whether
// a package claims the file; it may be nil when that is unknown.
func WhyNotQuarantine(path string, owned func(string) bool) string {
	for _, p := range []string{"/proc/", "/sys/", "/dev/"} {
		if strings.HasPrefix(path, p) {
			return "virtual file"
		}
	}
	if protectedFiles[path] {
		return "system file every login depends on: edit the bad line instead"
	}
	for _, d := range []string{"/etc/pam.d/", "/etc/security/"} {
		if strings.HasPrefix(path, d) {
			return "PAM config: removing it can lock everyone out, edit the bad line instead"
		}
	}
	dir, base := filepath.Split(path)
	if strings.HasPrefix(base, ".") && (strings.HasPrefix(dir, "/root/") || strings.HasPrefix(dir, "/home/")) {
		return "shell or ssh dotfile: edit the bad line instead"
	}
	if base == "authorized_keys" || base == "authorized_keys2" {
		return "remove the bad key instead of the whole file"
	}
	fi, err := os.Lstat(path)
	switch {
	case err != nil:
		return "gone already"
	case fi.IsDir():
		return "directory"
	}
	if owned != nil && owned(path) {
		return "owned by a package: reinstall it (rpm -qf / dpkg -S tells you which)"
	}
	return ""
}

// Editable reports whether path is a small text file worth opening in an
// editor.
func Editable(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	return !strings.ContainsRune(string(buf[:n]), 0)
}
