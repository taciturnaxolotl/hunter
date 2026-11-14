//go:build linux

package target

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// suspiciousLine matches things that should never show up in a cron line,
// unit, shell rc file or PAM stack on a competition box.
var suspiciousLine = regexp.MustCompile(`(?i)(/dev/tcp/|/dev/udp/|\bnc(at)?\b.*\s-[a-z]*[ec]\b|\bsocat\b|bash\s+-i|sh\s+-i\b|(curl|wget)[^|;]*\|\s*(ba|z|da)?sh|base64\s+(-d|--decode)|python[0-9.]*\s+-c|perl\s+-e|php\s+-r|mkfifo|LD_PRELOAD|/dev/shm/|(^|[\s='"])/tmp/|(^|[\s='"])/var/tmp/|\bchattr\s+\+i|\bmemfd|xxd\s+-r|openssl\s+s_client)`)

var aliasHijack = regexp.MustCompile(`^\s*alias\s+(sudo|su|ls|ps|ss|netstat|cat|passwd|ssh|top|kill|lsof|find|grep|rm|cd|systemctl|crontab|who|w|last|id)=(.*)$`)

// isAliasHijack ignores distro habits like alias rm='rm -i' and only flags
// an alias that swaps in a different program or chains extra commands.
func isAliasHijack(line string) bool {
	m := aliasHijack.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	name, val := m[1], strings.TrimSpace(m[2])
	if i := strings.Index(val, " 2>"); i >= 0 && (strings.HasPrefix(val, "'") || strings.HasPrefix(val, `"`)) {
		val = strings.TrimSpace(val[:i])
	}
	val = strings.Trim(val, `'"`)
	if strings.ContainsAny(val, ";|&`$<>") {
		return true
	}
	first := ""
	if f := strings.Fields(val); len(f) > 0 {
		first = strings.TrimPrefix(f[0], `\`)
		if first == "command" && len(f) > 1 {
			first = f[1]
		}
	}
	if name == "sudo" && strings.Contains(val, "-S") {
		return true // reads the password from stdin: classic credential grab
	}
	return first != name && filepath.Base(first) != name
}

func suspicious(s string) bool { return suspiciousLine.MatchString(s) }

func nonComment(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// --- accounts -------------------------------------------------------------

var allowedNSS = map[string]bool{
	"files": true, "compat": true, "systemd": true, "sss": true, "winbind": true, "ldap": true,
	"nis": true, "nisplus": true, "db": true, "myhostname": true, "mymachines": true, "resolve": true,
	"dns": true, "mdns": true, "mdns4": true, "mdns4_minimal": true, "mdns6": true, "mdns6_minimal": true,
	"usrfiles": true, "altfiles": true, "wins": true, "extrausers": true, "libvirt": true, "libvirt_guest": true,
}

var defaultNoLoginShell = regexp.MustCompile(`(nologin|/false|/sync|/shutdown|/halt)$`)

func (c *collector) checkAccounts() {
	knownBad := map[string]bool{}
	for _, u := range c.rules.Users {
		knownBad[u] = true
	}
	for _, e := range c.passwd {
		detail := fmt.Sprintf("uid=%d gid=%d home=%s shell=%s", e.UID, e.GID, e.Home, e.Shell)
		key := "user:" + e.Name
		switch {
		case e.UID == 0 && e.Name != "root":
			c.add("accounts", key, snapshot.Crit, "extra uid 0 account", detail, "")
		case knownBad[e.Name]:
			c.add("accounts", key, snapshot.Crit, "account name from known red team kit", detail, "")
		case e.UID > 0 && e.UID < 1000 && !defaultNoLoginShell.MatchString(e.Shell) && e.Shell != "" && e.Name != "root":
			c.add("accounts", key, snapshot.Warn, "system account has a login shell", detail, "")
		default:
			c.add("accounts", key, snapshot.Info, "account", detail, "")
		}
	}

	// NSS: an extra source can hide users that /etc/passwd never shows.
	if b, err := os.ReadFile("/etc/nsswitch.conf"); err == nil {
		for _, l := range nonComment(string(b)) {
			db, rest, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			db = strings.TrimSpace(db)
			if db != "passwd" && db != "group" && db != "shadow" && db != "gshadow" && db != "initgroups" {
				continue
			}
			for _, src := range strings.Fields(rest) {
				if strings.HasPrefix(src, "[") {
					continue
				}
				if !allowedNSS[src] {
					c.add("accounts", "nss:"+db+":"+src, snapshot.Crit, "unknown NSS source (hidden-user backdoor like libnss_cache)", l, "")
				}
			}
			c.add("accounts", "nsswitch:"+db, snapshot.Info, "nsswitch line", l, "")
		}
	}

	// shadow: who has a usable password, and did it change.
	if b, err := os.ReadFile("/etc/shadow"); err == nil {
		uidOf := map[string]int{}
		for _, e := range c.passwd {
			uidOf[e.Name] = e.UID
		}
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) < 2 || f[0] == "" {
				continue
			}
			name, hash := f[0], f[1]
			usable := hash != "" && !strings.HasPrefix(hash, "!") && !strings.HasPrefix(hash, "*")
			key := "shadow:" + name
			hh := short(sha256Bytes([]byte(hash)))
			bad := false
			for _, s := range c.rules.Shadow {
				if strings.Contains(hash, s) {
					bad = true
				}
			}
			switch {
			case bad:
				c.add("accounts", key, snapshot.Crit, "password hash from known red team kit", "salt "+saltOf(hash), hh)
			case hash == "":
				c.add("accounts", key, snapshot.Crit, "empty password (logs in with no password)", "", hh)
			case usable && name != "root" && uidOf[name] > 0 && uidOf[name] < 1000:
				c.add("accounts", key, snapshot.Warn, "system account has a password set", "salt "+saltOf(hash), hh)
			case usable:
				c.add("accounts", key, snapshot.Info, "password set", "", hh)
			default:
				c.add("accounts", key, snapshot.Info, "password locked", "", hh)
			}
		}
	} else {
		c.errf("read /etc/shadow: %v (run as root)", err)
	}

	if b, err := os.ReadFile("/etc/shells"); err == nil {
		for _, l := range nonComment(string(b)) {
			sev, msg := snapshot.Info, "allowed login shell"
			if strings.HasSuffix(l, "/false") || strings.HasSuffix(l, "nologin") {
				sev, msg = snapshot.Crit, "non-shell listed in /etc/shells (lets locked accounts log in)"
			}
			c.add("accounts", "shells:"+l, sev, msg, l, "")
		}
	}

	sudoFiles := append([]string{"/etc/sudoers"}, globAll("/etc/sudoers.d/*")...)
	for _, f := range sudoFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range nonComment(string(b)) {
			if strings.HasPrefix(l, "Defaults") || strings.HasPrefix(l, "@include") || strings.HasPrefix(l, "#include") {
				continue
			}
			key := "sudo:" + f + ":" + short(sha256Bytes([]byte(l)))
			sev, msg := snapshot.Info, "sudoers rule"
			switch {
			case regexp.MustCompile(`%#\d+`).MatchString(l):
				sev, msg = snapshot.Warn, "sudoers rule for a numeric group id (hides which group)"
			case strings.Contains(l, "NOPASSWD"):
				sev, msg = snapshot.Warn, "passwordless sudo"
			}
			c.add("accounts", key, sev, msg, l, "")
		}
	}

	if b, err := os.ReadFile("/etc/group"); err == nil {
		priv := map[string]bool{"root": true, "wheel": true, "sudo": true, "admin": true, "adm": true, "docker": true, "lxd": true, "disk": true, "shadow": true}
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) < 4 || !priv[f[0]] || f[3] == "" {
				continue
			}
			c.add("accounts", "group:"+f[0], snapshot.Info, "privileged group members", f[3], "")
		}
	}
}

func saltOf(h string) string {
	p := strings.Split(h, "$")
	if len(p) >= 4 {
		return "$" + p[1] + "$" + p[2] + "$"
	}
	return "?"
}

// --- shells ---------------------------------------------------------------

func (c *collector) checkShells() {
	for _, p := range []string{"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/true", "/usr/bin/true"} {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		real, _ := filepath.EvalSymlinks(p)
		b, _ := readLimited(p, 8<<20)
		key := "shell:" + p
		detail := fmt.Sprintf("size=%d sha256=%s -> %s", fi.Size(), short(sha256Bytes(b)), real)
		switch {
		case strings.Contains(string(b), "GNU bash") || strings.Contains(string(b), "BusyBox"):
			c.add("shells", key, snapshot.Crit, "nologin/false replaced by a real shell", detail, "")
		case fi.Size() > 1<<20:
			c.add("shells", key, snapshot.Crit, "nologin/false is suspiciously large", detail, "")
		case strings.Contains(p, "nologin") && !strings.Contains(string(b), "not available") && len(b) > 0:
			c.add("shells", key, snapshot.Warn, "nologin lacks its usual denial message", detail, "")
		default:
			c.add("shells", key, snapshot.Info, "shell stub", detail, sha256Bytes(b))
		}
	}
	critical := []string{
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/nsswitch.conf",
		"/etc/ssh/sshd_config", "/etc/ld.so.preload", "/etc/shells", "/etc/hosts", "/etc/resolv.conf",
		"/usr/sbin/sshd", "/usr/bin/chpasswd", "/usr/sbin/chpasswd", "/usr/sbin/nologin", "/sbin/nologin",
		"/bin/false", "/usr/bin/false", "/root/.ssh/authorized_keys", "/etc/crontab",
	}
	critical = append(critical, globAll("/etc/pam.d/*", "/etc/sudoers.d/*", "/etc/cron.d/*", "/home/*/.ssh/authorized_keys")...)
	for _, p := range critical {
		flags, err := fsFlags(p)
		if err != nil || flags&(fsImmutableFl|fsAppendFl) == 0 {
			continue
		}
		c.add("shells", "chattr:"+p, snapshot.Warn, "file is "+flagString(flags)+" (blocks fixes; ours or theirs?)", p, "")
	}
}

// --- preload --------------------------------------------------------------

func (c *collector) checkPreload() {
	if b, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		for _, l := range nonComment(string(b)) {
			c.add("preload", "ld.so.preload:"+l, snapshot.Crit, "library force-loaded into every process", l, "")
		}
		if len(nonComment(string(b))) == 0 {
			c.add("preload", "ld.so.preload", snapshot.Warn, "/etc/ld.so.preload exists (empty)", "", "")
		}
	}
	for _, f := range append([]string{"/etc/ld.so.conf"}, globAll("/etc/ld.so.conf.d/*")...) {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		c.add("preload", "ld.so.conf:"+f, snapshot.Info, "linker search path config", strings.Join(nonComment(string(b)), " "), sha256Bytes(b))
		for _, l := range nonComment(string(b)) {
			if strings.HasPrefix(l, "/tmp") || strings.HasPrefix(l, "/var/tmp") || strings.HasPrefix(l, "/dev/shm") || strings.HasPrefix(l, "/home") {
				c.add("preload", "ld.so.conf:"+f+":"+l, snapshot.Crit, "linker searches a writable directory", l, "")
			}
		}
	}
	if v := os.Getenv("LD_PRELOAD"); v != "" {
		c.add("preload", "env:self", snapshot.Crit, "LD_PRELOAD set in hunter's own environment", v, "")
	}
}

// --- PAM ------------------------------------------------------------------

var pamDirs = []string{
	"/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security",
	"/lib/x86_64-linux-gnu/security", "/usr/lib/x86_64-linux-gnu/security",
	"/lib/aarch64-linux-gnu/security", "/usr/lib/aarch64-linux-gnu/security",
}

func (c *collector) checkPAM() {
	for _, f := range globAll("/etc/pam.d/*", "/etc/pam.conf") {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		c.add("pam", "file:"+f, snapshot.Info, "pam config", "", sha256Bytes(b))
		for _, l := range nonComment(string(b)) {
			fields := strings.Fields(l)
			mod := ""
			for i, fl := range fields {
				if strings.Contains(fl, ".so") || (i > 0 && strings.HasPrefix(fl, "/")) {
					mod = fl
					break
				}
			}
			key := "line:" + f + ":" + short(sha256Bytes([]byte(l)))
			switch {
			case strings.Contains(l, "pam_exec") || strings.Contains(l, "pam_script"):
				c.add("pam", key, snapshot.Crit, "PAM runs an external program (credential stealer pattern)", l, "")
			case strings.HasPrefix(mod, "/") && !underAny(mod, pamDirs):
				c.add("pam", key, snapshot.Crit, "PAM module loaded from a non-standard path", l, "")
			case suspicious(l):
				c.add("pam", key, snapshot.Crit, "suspicious PAM line", l, "")
			}
		}
	}
	for _, d := range pamDirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		real, _ := filepath.EvalSymlinks(d)
		if real != "" && real != d && exists(real) {
			// merged /lib -> /usr/lib: report once under the real path
			if contains(pamDirs, real) {
				continue
			}
		}
		for _, e := range ents {
			p := filepath.Join(d, e.Name())
			if !e.Type().IsRegular() {
				continue
			}
			sev, msg := snapshot.Info, "pam module"
			if !c.isOwned(p) {
				sev, msg = snapshot.Crit, "PAM module not owned by any package"
			}
			c.add("pam", "module:"+p, sev, msg, "", sha256File(p))
		}
	}
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// --- SSH ------------------------------------------------------------------

func sshFingerprint(blob string) string {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "badblob:" + short(sha256Bytes([]byte(blob)))
	}
	s := sha256.Sum256(raw)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(s[:]), "=")
}

var keyTypeRe = regexp.MustCompile(`^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-[a-z0-9@.-]+)$`)

func (c *collector) checkSSH() {
	badKeys := map[string]bool{}
	for _, k := range c.rules.PubKeys {
		badKeys[k] = true
	}
	var files []string
	for _, h := range c.homes() {
		files = append(files, filepath.Join(h, ".ssh/authorized_keys"), filepath.Join(h, ".ssh/authorized_keys2"))
		if exists(filepath.Join(h, ".ssh/rc")) {
			c.add("ssh", "rc:"+h, snapshot.Warn, "~/.ssh/rc runs on every login", filepath.Join(h, ".ssh/rc"), sha256File(filepath.Join(h, ".ssh/rc")))
		}
	}
	files = append(files, "/etc/ssh/.ssh/authorized_keys", "/etc/ssh/authorized_keys")
	files = append(files, globAll("/etc/ssh/authorized_keys.d/*")...)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.HasPrefix(f, "/etc/ssh/.ssh") {
			c.add("ssh", "akfile:"+f, snapshot.Crit, "authorized_keys for the sshd account", f, "")
		}
		for _, l := range nonComment(string(b)) {
			fields := strings.Fields(l)
			typ, blob, comment, opts := "", "", "", ""
			for i, fl := range fields {
				if keyTypeRe.MatchString(fl) && i+1 < len(fields) {
					typ, blob = fl, fields[i+1]
					comment = strings.Join(fields[i+2:], " ")
					opts = strings.Join(fields[:i], " ")
					break
				}
			}
			if blob == "" {
				c.add("ssh", "ak:"+f+":unparsed:"+short(sha256Bytes([]byte(l))), snapshot.Warn, "unparseable authorized_keys line", l, "")
				continue
			}
			fp := sshFingerprint(blob)
			key := "ak:" + f + ":" + fp
			detail := strings.TrimSpace(typ + " " + comment + " " + opts)
			switch {
			case badKeys[blob]:
				c.add("ssh", key, snapshot.Crit, "red team master key (ccdc_master)", detail, "")
			case strings.Contains(opts, "command=") && suspicious(opts):
				c.add("ssh", key, snapshot.Crit, "key with a suspicious forced command", detail, "")
			default:
				c.add("ssh", key, snapshot.Info, "authorized key", detail, "")
			}
		}
	}

	cfgs := append([]string{"/etc/ssh/sshd_config"}, globAll("/etc/ssh/sshd_config.d/*")...)
	for _, f := range cfgs {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		c.add("ssh", "config:"+f, snapshot.Info, "sshd config file", "", sha256Bytes(b))
		for _, l := range nonComment(string(b)) {
			kw := strings.ToLower(strings.Fields(l)[0])
			val := strings.TrimSpace(strings.TrimPrefix(l, strings.Fields(l)[0]))
			key := "opt:" + f + ":" + kw
			switch kw {
			case "authorizedkeyscommand", "authorizedprincipalscommand":
				// systemd-userdb, sssd and cloud agents do this legitimately
				// with packaged helpers; the red team wrapper used its own script.
				prog := ""
				if f := strings.Fields(val); len(f) > 0 {
					prog = f[0]
				}
				if prog != "" && prog != "none" && exists(prog) && c.owned != nil && c.isOwned(prog) {
					c.add("ssh", key, snapshot.Warn, "sshd asks a packaged program for valid keys (review)", l, "")
				} else if prog != "none" {
					c.add("ssh", key, snapshot.Crit, "sshd asks a program for valid keys (master-key backdoor pattern)", l, "")
				}
			case "permitemptypasswords":
				if strings.EqualFold(val, "yes") {
					c.add("ssh", key, snapshot.Crit, "empty passwords allowed", l, "")
				}
			case "authorizedkeysfile":
				if v := strings.Join(strings.Fields(val), " "); v == ".ssh/authorized_keys" || v == ".ssh/authorized_keys .ssh/authorized_keys2" || v == "%h/.ssh/authorized_keys" {
					c.add("ssh", key, snapshot.Info, kw, l, "")
				} else {
					c.add("ssh", key, snapshot.Warn, "custom AuthorizedKeysFile", l, "")
				}
			case "forcecommand", "trustedusercakeys", "authorizedprincipalsfile":
				c.add("ssh", key, snapshot.Warn, "review: "+kw, l, "")
			case "permitrootlogin", "passwordauthentication", "pubkeyauthentication", "allowusers", "denyusers", "allowgroups", "port", "listenaddress":
				c.add("ssh", key, snapshot.Info, kw, l, "")
			}
		}
	}

	// sshd started with injected -o options never shows up in sshd_config.
	for _, p := range listPids() {
		comm := readTrim(fmt.Sprintf("/proc/%d/comm", p))
		if comm != "sshd" && !strings.HasPrefix(comm, "sshd") {
			continue
		}
		cmd := readCmdline(p)
		if strings.Contains(cmd, "AuthorizedKeysCommand") || strings.Contains(cmd, "sshd.orig") {
			c.add("ssh", fmt.Sprintf("sshd-cmdline:%d", p), snapshot.Crit, "sshd running with injected options (wrapper backdoor)", cmd, "")
		}
	}
}
