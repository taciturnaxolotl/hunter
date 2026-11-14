//go:build linux

package target

import (
	"bytes"
	"fmt"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var walkSkip = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true, "/run": true, "/snap": true, "/nix/store": true,
	"/var/lib/docker": true, "/var/lib/containers": true, "/var/lib/containerd": true,
	"/var/lib/flatpak": true, "/var/cache": true, "/mnt": true, "/media": true,
	"/root/.quarantine": true, "/var/lib/lxcfs": true, "/var/lib/kubelet/pods": true,
}

// Setuid files that are normal when a package owns them.
var knownSuid = map[string]bool{
	"su": true, "sudo": true, "sudoedit": true, "passwd": true, "chsh": true, "chfn": true, "newgrp": true,
	"gpasswd": true, "mount": true, "umount": true, "pkexec": true, "ping": true, "ping6": true,
	"crontab": true, "at": true, "fusermount": true, "fusermount3": true, "ssh-keysign": true,
	"polkit-agent-helper-1": true, "dbus-daemon-launch-helper": true, "unix_chkpwd": true,
	"pam_timestamp_check": true, "chage": true, "expiry": true, "wall": true, "write": true,
	"ssh-agent": true, "locate": true, "plocate": true, "mlocate": true, "Xorg.wrap": true,
	"userhelper": true, "sg": true, "newuidmap": true, "newgidmap": true, "usernetctl": true,
	"chrome-sandbox": true, "snap-confine": true, "mount.nfs": true, "mount.cifs": true,
	"pt_chown": true, "utempter": true, "staprun": true, "vmware-user-suid-wrapper": true,
	"lockdev": true, "postdrop": true, "postqueue": true, "dotlockfile": true, "mail-lock": true,
	"mail-unlock": true, "mail-touchlock": true, "bsd-write": true, "screen": true, "netreport": true,
	"cockpit-session": true, "Xorg": true, "kismet_cap_linux_wifi": true, "ntfs-3g": true, "traceroute6.iputils": true,
	"mount.ecryptfs_private": true, "gnome-keyring-daemon": true, "pppd": true, "exim4": true, "procmail": true,
	"sendmail": true, "lppasswd": true, "fping": true, "fping6": true, "doas": true, "spice-client-glib-usb-acl-helper": true,
	"qemu-bridge-helper": true, "dmcrypt-get-device": true, "chkpwd": true, "unix2_chkpwd": true, "pam_extrausers_chkpwd": true, "nvidia-modprobe": true,
	"kgrantpty": true, "ksu": true, "userns-helper": true, "crond": true, "slocate": true, "chromium-sandbox": true,
}

var binPrefixes = []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/usr/libexec/", "/usr/local/libexec/", "/opt/"}

var stompPrefixes = []string{"/etc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/var/spool/", "/boot/"}

func hasAnyPrefix(p string, prefixes []string) bool {
	for _, x := range prefixes {
		if strings.HasPrefix(p, x) {
			return true
		}
	}
	return false
}

func isInterpreter(base string) bool {
	for _, n := range []string{"bash", "sh", "dash", "zsh", "ksh", "busybox", "python", "perl", "ruby", "php", "node", "lua", "tclsh", "gdb", "vim", "vi", "find", "env", "awk", "gawk", "nmap", "less", "more", "tar", "cp", "chroot", "ip"} {
		if base == n || strings.HasPrefix(base, n+"2") || strings.HasPrefix(base, n+"3") || strings.HasPrefix(base, n+".") {
			return true
		}
	}
	return false
}

func (c *collector) checkFS() {
	cutoff := c.now.Add(-c.since)
	stomps, stompCap := 0, 300
	tempHits := 0
	walk := func(root string) {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if walkSkip[p] && p != root {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			mode := fi.Mode()
			base := filepath.Base(p)
			execBit := mode.Perm()&0o111 != 0
			mtime, ctime := fileTimes(fi)
			uid, _ := fileOwner(fi)

			// setuid / setgid
			if mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
				kind := "setuid"
				if mode&os.ModeSetuid == 0 {
					kind = "setgid"
				}
				detail := fmt.Sprintf("%s mode=%s uid=%d size=%d", p, mode, uid, fi.Size())
				key := "suid:" + p
				h := sha256File(p)
				switch {
				case inTempDir(p) || strings.HasPrefix(p, "/home/") || strings.HasPrefix(p, "/root/"):
					c.add("fs", key, snapshot.Crit, kind+" file in a user/temp dir", detail, h)
				case c.owned != nil && !c.isOwned(p):
					c.add("fs", key, snapshot.Crit, kind+" file not owned by any package (planted rootshell?)", detail, h)
				case kind == "setuid" && isInterpreter(base):
					c.add("fs", key, snapshot.Crit, "setuid on a shell/interpreter/GTFOBin = root shell", detail, h)
				case !knownSuid[base]:
					c.add("fs", key, snapshot.Warn, kind+" on a binary that normally is not", detail, h)
				default:
					c.add("fs", key, snapshot.Info, kind+" binary", detail, h)
				}
			}

			// file capabilities
			if execBit {
				if caps := fileCaps(p); len(caps) > 0 {
					sev := snapshot.Warn
					for _, cp := range caps {
						if dangerousCaps[cp] {
							sev = snapshot.Crit
						}
					}
					if sev == snapshot.Warn && c.isOwned(p) {
						sev = snapshot.Info
					}
					c.add("fs", "cap:"+p, sev, "file capabilities "+strings.Join(caps, ","), p, strings.Join(caps, ","))
				}
			}

			// executables and hidden files in temp dirs
			if inTempDir(p) && tempHits < 200 {
				head := readHead(p, 4)
				if execBit || isELF(head) {
					tempHits++
					c.add("fs", "tmpexec:"+p, snapshot.Crit, "executable in a temp dir", fmt.Sprintf("%s size=%d", p, fi.Size()), sha256File(p))
				} else if strings.HasPrefix(base, ".") {
					tempHits++
					c.add("fs", "tmphidden:"+p, snapshot.Warn, "hidden file in a temp dir", fmt.Sprintf("%s size=%d", p, fi.Size()), "")
				}
			}

			// timestomping: inode changed recently, mtime claims it is old.
			// Packaged files are covered by package verification (which
			// compares contents, not mtime), so only unowned files are
			// checked, and only programs and libraries (config edits already
			// show up as hash changes in the diff).
			stompable := (c.owned == nil || !c.isOwned(p)) && (execBit || strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.")) && !strings.HasPrefix(base, "ld.so")
			if stompable && hasAnyPrefix(p, stompPrefixes) && ctime.After(cutoff) && mtime.Before(cutoff) {
				stomps++
				if stomps <= stompCap {
					c.add("fs", "stomp:"+p, snapshot.Warn, "changed recently but mtime says old (timestomp, or a package reinstall)",
						fmt.Sprintf("%s mtime=%s ctime=%s", p, mtime.UTC().Format("2006-01-02 15:04"), ctime.UTC().Format("2006-01-02 15:04")), "")
				}
			}

			// binaries in system bin dirs: unpackaged, UPX packed
			if execBit && hasAnyPrefix(p, binPrefixes) {
				unowned := c.owned != nil && !c.isOwned(p) && !strings.HasPrefix(p, "/opt/")
				head := readHead(p, 4096)
				if isELF(head) && bytes.Contains(head, []byte("UPX!")) {
					sev := snapshot.Warn
					if unowned {
						sev = snapshot.Crit
					}
					c.add("fs", "upx:"+p, sev, "UPX-packed executable (red team fake daemons were packed)", p, sha256File(p))
				} else if unowned && (isELF(head) || bytes.HasPrefix(head, []byte("#!"))) {
					c.add("fs", "unowned:"+p, snapshot.Warn, "executable no package owns", fmt.Sprintf("%s size=%d", p, fi.Size()), sha256File(p))
				}
			}

			// NSS modules and shared objects hiding next to system libraries
			if strings.HasPrefix(base, "libnss_") && c.owned != nil && !c.isOwned(p) {
				c.add("fs", "nss:"+p, snapshot.Crit, "NSS module no package owns (hidden users)", p, sha256File(p))
			}

			// python startup hooks (marvin had a sitecustomize.py; April had trojaned .pyc)
			if base == "sitecustomize.py" || base == "usercustomize.py" {
				sev := snapshot.Warn
				if c.owned != nil && !c.isOwned(p) {
					sev = snapshot.Crit
				}
				c.add("fs", "pyhook:"+p, sev, "python startup hook runs in every python process (dnf too)", p, sha256File(p))
			}
			if strings.HasSuffix(base, ".pth") && (strings.Contains(p, "site-packages") || strings.Contains(p, "dist-packages")) {
				if b, _ := readLimited(p, 64<<10); bytes.Contains(b, []byte("import ")) {
					sev := snapshot.Warn
					if c.isOwned(p) {
						sev = snapshot.Info
					}
					c.add("fs", "pth:"+p, sev, ".pth file executes code at python startup", truncate(string(b), 200), sha256Bytes(b))
				}
			}
			return nil
		})
	}
	walk("/")
	walk("/dev/shm")
	walk("/run/shm")
	if stomps > stompCap {
		c.add("fs", "stomp:summary", snapshot.Warn, fmt.Sprintf("%d timestomp candidates, first %d listed (big numbers usually mean a package update)", stomps, stompCap), "", "")
	}
}

// --- indicator pack -------------------------------------------------------

var iocScanDirs = []string{
	"/etc", "/tmp", "/var/tmp", "/dev/shm", "/root", "/home", "/run/systemd", "/usr/local", "/opt",
	"/var/spool", "/usr/lib/systemd", "/lib/systemd", "/var/www", "/srv",
}

func (c *collector) checkIOC() {
	seenReal := map[string]bool{}
	for _, g := range c.rules.Paths {
		for _, p := range globAll(g) {
			if r := c.res.norm(p); seenReal[r] {
				continue
			} else {
				seenReal[r] = true
			}
			fi, err := os.Lstat(p)
			if err != nil {
				continue
			}
			c.add("ioc", "path:"+p, snapshot.Crit, "path from known red team kit exists", fmt.Sprintf("%s size=%d mode=%s", p, fi.Size(), fi.Mode()), "")
		}
	}
	for _, rule := range c.rules.Files {
		for _, p := range globAll(rule.Glob) {
			b, err := readLimited(p, 16<<20)
			if err != nil {
				continue
			}
			for _, s := range rule.Contains {
				if bytes.Contains(b, []byte(s)) {
					c.add("ioc", "contains:"+p+":"+s, snapshot.Crit, "file contains a known red team marker", fmt.Sprintf("%s contains %q", p, s), "")
				}
			}
		}
	}
	if len(c.rules.Strings) == 0 {
		return
	}
	needles := make([][]byte, len(c.rules.Strings))
	for i, s := range c.rules.Strings {
		needles[i] = []byte(s)
	}
	budget := int64(1 << 30)
	hits := 0
	scanned := map[string]bool{}
	for _, root := range iocScanDirs {
		real, err := filepath.EvalSymlinks(root)
		if err != nil || scanned[real] {
			continue
		}
		scanned[real] = true
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if budget <= 0 || hits > 300 {
				return filepath.SkipAll
			}
			if d.IsDir() {
				b := filepath.Base(p)
				// our own repo carries the indicator pack; do not match ourselves
				if walkSkip[p] || b == ".cache" || b == "node_modules" || b == ".git" || exists(filepath.Join(p, "rules/ccdc-kit.json")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || p == c.self {
				return nil
			}
			fi, err := d.Info()
			if err != nil || fi.Size() > 4<<20 {
				return nil
			}
			b, err := readLimited(p, 4<<20)
			if err != nil {
				return nil
			}
			budget -= int64(len(b))
			for i, n := range needles {
				if bytes.Contains(b, n) {
					hits++
					c.add("ioc", "string:"+p+":"+c.rules.Strings[i], snapshot.Crit, "file mentions a known red team indicator",
						fmt.Sprintf("%s contains %q", p, c.rules.Strings[i]), "")
				}
			}
			return nil
		})
	}
}
