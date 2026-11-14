//go:build linux

package target

import (
	"fmt"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var unitDirs = []string{
	"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
	"/usr/local/lib/systemd/system", "/etc/systemd/user", "/usr/lib/systemd/user", "/run/systemd/transient",
	"/run/systemd/generator", "/run/systemd/generator.late", "/etc/systemd/system.control", "/run/systemd/system.control",
}

var absPathRe = regexp.MustCompile(`(^|[\s=@'"])(/[A-Za-z0-9._/+-]+)`)

// execTargets pulls absolute paths out of a command line so we can check
// whether the thing root runs is writable by someone else.
func execTargets(s string) []string {
	var out []string
	for _, m := range absPathRe.FindAllStringSubmatch(s, -1) {
		p := m[2]
		if strings.HasPrefix(p, "/dev/") || strings.HasPrefix(p, "/proc/") {
			continue
		}
		out = append(out, p)
	}
	return out
}

// checkWritableTarget flags a root-run script that a non-root user can
// edit: on foghorn the web user owned a script root's cron ran.
func (c *collector) checkWritableTarget(check, origin, line string) {
	for _, p := range execTargets(line) {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		uid, _ := fileOwner(fi)
		if uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			c.add(check, "writable:"+p, snapshot.Crit, "root runs a file that non-root can modify (privesc)",
				fmt.Sprintf("%s uid=%d mode=%s from %s", p, uid, fi.Mode().Perm(), origin), "")
		}
	}
}

func (c *collector) checkSystemd() {
	homes := c.homes()
	dirs := append([]string(nil), unitDirs...)
	for _, h := range homes {
		dirs = append(dirs, filepath.Join(h, ".config/systemd/user"))
	}
	seenReal := map[string]bool{}
	for _, d := range dirs {
		realDir, err := filepath.EvalSymlinks(d)
		if err != nil || seenReal[realDir] {
			continue
		}
		seenReal[realDir] = true
		isUserHome := strings.Contains(d, "/.config/systemd/user")
		vendor := strings.HasPrefix(realDir, "/usr/lib") || strings.HasPrefix(realDir, "/lib")
		_ = filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				return nil
			}
			name := e.Name()
			parent := filepath.Base(filepath.Dir(p))
			if e.Type()&os.ModeSymlink != 0 {
				target, _ := os.Readlink(p)
				switch {
				case target == "/dev/null":
					c.add("systemd", "masked:"+p, snapshot.Warn, "unit masked", name, "")
				case strings.HasSuffix(parent, ".wants") || strings.HasSuffix(parent, ".requires"):
					c.add("systemd", "enabled:"+p, snapshot.Info, "unit enabled", parent+"/"+name+" -> "+target, "")
				}
				return nil
			}
			if !e.Type().IsRegular() {
				return nil
			}
			fi, err := e.Info()
			if err != nil {
				return nil
			}
			b, _ := readLimited(p, 256<<10)
			hash := sha256Bytes(b)
			key := "unit:" + p
			switch {
			case isUserHome:
				c.add("systemd", key, snapshot.Warn, "per-user systemd unit (fires on next login of that user)", firstExec(string(b)), hash)
			case fi.Size() == 0 && strings.HasSuffix(name, ".service"):
				c.add("systemd", key, snapshot.Warn, "empty unit file (service sabotaged)", name, hash)
			case vendor && !c.isOwned(p) && !strings.HasPrefix(p, "/run/"):
				c.add("systemd", key, snapshot.Warn, "vendor unit not owned by any package", firstExec(string(b)), hash)
			default:
				msg := "unit file"
				if strings.HasSuffix(parent, ".d") {
					msg = "unit drop-in"
				}
				c.add("systemd", key, snapshot.Info, msg, firstExec(string(b)), hash)
			}
			for _, l := range nonComment(string(b)) {
				if !strings.Contains(l, "=") {
					continue
				}
				k, v, _ := strings.Cut(l, "=")
				k = strings.TrimSpace(k)
				lk := "line:" + p + ":" + short(sha256Bytes([]byte(l)))
				if strings.HasPrefix(k, "Exec") || k == "Environment" || k == "EnvironmentFile" {
					if strings.Contains(v, "LD_PRELOAD") {
						c.add("systemd", lk, snapshot.Crit, "unit injects LD_PRELOAD", l, "")
					} else if suspicious(v) {
						c.add("systemd", lk, snapshot.Crit, "suspicious command in unit", l, "")
					}
					if strings.HasPrefix(k, "Exec") && !vendor {
						c.checkWritableTarget("systemd", p, v)
					}
				}
			}
			return nil
		})
	}
}

func firstExec(unit string) string {
	for _, l := range strings.Split(unit, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "ExecStart=") {
			return t
		}
	}
	return ""
}

var (
	promptHook   = regexp.MustCompile(`PROMPT_COMMAND\+?=`)
	benignPrompt = regexp.MustCompile(`PROMPT_COMMAND\+?=\(?(['"]?printf |/etc/sysconfig/bash-prompt-|__vte_prompt_command|__systemd_osc_context|''\))|declare -p PROMPT_COMMAND|-z "\$PROMPT_COMMAND"`)
	debugTrap    = regexp.MustCompile(`trap\s+.*\bDEBUG\b`)
)

var cronEnvLine = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)

func (c *collector) checkCron() {
	files := globAll(
		"/etc/crontab", "/etc/anacrontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
		"/etc/cron.weekly/*", "/etc/cron.monthly/*", "/var/spool/cron/*", "/var/spool/cron/crontabs/*",
		"/var/spool/cron/tabs/*", "/var/spool/at/*", "/var/spool/cron/atjobs/*", "/etc/incron.d/*",
		"/var/spool/incron/*",
	)
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		b, _ := readLimited(f, 256<<10)
		isScriptDir := strings.Contains(f, "/cron.hourly/") || strings.Contains(f, "/cron.daily/") ||
			strings.Contains(f, "/cron.weekly/") || strings.Contains(f, "/cron.monthly/")
		user := strings.HasPrefix(f, "/var/spool/")
		sev, msg := snapshot.Info, "cron file"
		if user {
			sev, msg = snapshot.Warn, "per-user crontab or at job"
		}
		if isScriptDir && !c.isOwned(f) {
			sev, msg = snapshot.Warn, "cron script not owned by any package"
		}
		c.add("cron", "file:"+f, sev, msg, "", sha256Bytes(b))
		if isScriptDir {
			for _, l := range nonComment(string(b)) {
				if suspicious(l) {
					c.add("cron", "line:"+f+":"+short(sha256Bytes([]byte(l))), snapshot.Crit, "suspicious command in cron script", l, "")
				}
			}
			continue
		}
		for _, l := range nonComment(string(b)) {
			if cronEnvLine.MatchString(l) {
				continue
			}
			key := "line:" + f + ":" + short(sha256Bytes([]byte(l)))
			if suspicious(l) {
				c.add("cron", key, snapshot.Crit, "suspicious cron entry", l, "")
			} else {
				c.add("cron", key, snapshot.Info, "cron entry", l, "")
			}
			c.checkWritableTarget("cron", f, l)
		}
	}
}

func (c *collector) checkInitFiles() {
	files := globAll(
		"/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/bashrc", "/etc/bash.bash_logout",
		"/etc/environment", "/etc/rc.local", "/etc/rc.d/rc.local", "/etc/zshrc", "/etc/zsh/*", "/etc/csh.cshrc",
		"/etc/security/pam_env.conf", "/etc/NetworkManager/dispatcher.d/*", "/etc/NetworkManager/dispatcher.d/*/*",
		"/etc/udev/rules.d/*", "/etc/update-motd.d/*", "/etc/motd.d/*", "/etc/apt/apt.conf.d/*",
		"/etc/dnf/plugins/*", "/etc/yum/pluginconf.d/*", "/etc/X11/Xsession.d/*", "/etc/xdg/autostart/*",
		"/etc/modules-load.d/*", "/etc/modprobe.d/*", "/etc/sysctl.d/*", "/etc/sysctl.conf",
		"/etc/ssh/sshrc", "/etc/hosts", "/etc/resolv.conf", "/etc/hosts.allow", "/etc/hosts.deny",
	)
	for _, h := range c.homes() {
		for _, n := range []string{".bashrc", ".bash_profile", ".profile", ".bash_login", ".bash_logout", ".zshrc", ".zprofile", ".config/autostart/*", ".pam_environment"} {
			files = append(files, globAll(filepath.Join(h, n))...)
		}
		hist := filepath.Join(h, ".bash_history")
		if t, err := os.Readlink(hist); err == nil && t == "/dev/null" {
			c.add("init", "history:"+hist, snapshot.Warn, "shell history symlinked to /dev/null (anti-forensics)", hist, "")
		}
	}
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		b, _ := readLimited(f, 256<<10)
		sev, msg := snapshot.Info, "startup/config file"
		switch {
		case f == "/etc/ssh/sshrc":
			sev, msg = snapshot.Warn, "/etc/ssh/sshrc runs on every SSH login"
		case (f == "/etc/rc.local" || f == "/etc/rc.d/rc.local") && len(nonComment(string(b))) > 1:
			sev, msg = snapshot.Warn, "rc.local has commands"
		}
		c.add("init", "file:"+f, sev, msg, "", sha256Bytes(b))
		for _, l := range nonComment(string(b)) {
			key := "line:" + f + ":" + short(sha256Bytes([]byte(l)))
			switch {
			case isAliasHijack(l):
				c.add("init", key, snapshot.Crit, "alias hijacks a command you rely on", l, "")
			case promptHook.MatchString(l) && (!benignPrompt.MatchString(l) || !c.isOwned(f)), debugTrap.MatchString(l):
				c.add("init", key, snapshot.Warn, "runs code before every prompt/command", l, "")
			case suspicious(l):
				c.add("init", key, snapshot.Crit, "suspicious line in startup file", l, "")
			}
		}
	}
}
