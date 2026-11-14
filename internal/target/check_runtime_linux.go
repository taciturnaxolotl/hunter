//go:build linux

package target

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func listPids() []int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

func readTrim(p string) string {
	b, _ := readLimited(p, 4096)
	return strings.TrimSpace(string(b))
}

func readCmdline(pid int) string {
	b, _ := readLimited(fmt.Sprintf("/proc/%d/cmdline", pid), 4096)
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

type procInfo struct {
	pid, ppid, uid int
	comm, exe, cmd string
	cwd            string
	foreignMountNS bool
}

var selfMountNS, _ = os.Readlink("/proc/self/ns/mnt")

func readProc(pid int) (procInfo, bool) {
	p := procInfo{pid: pid}
	base := fmt.Sprintf("/proc/%d", pid)
	status, err := os.ReadFile(base + "/status")
	if err != nil {
		return p, false
	}
	for _, l := range strings.Split(string(status), "\n") {
		k, v, _ := strings.Cut(l, ":")
		v = strings.TrimSpace(v)
		switch k {
		case "PPid":
			p.ppid, _ = strconv.Atoi(v)
		case "Uid":
			if f := strings.Fields(v); len(f) > 0 {
				p.uid, _ = strconv.Atoi(f[0])
			}
		}
	}
	p.comm = readTrim(base + "/comm")
	p.exe, _ = os.Readlink(base + "/exe")
	p.cmd = readCmdline(pid)
	p.cwd, _ = os.Readlink(base + "/cwd")
	if ns, err := os.Readlink(base + "/ns/mnt"); err == nil && selfMountNS != "" && ns != selfMountNS {
		p.foreignMountNS = true
	}
	return p, true
}

var kthreadNames = []string{"kworker", "ksoftirqd", "kthreadd", "migration", "rcu_", "kswapd", "watchdog/", "jbd2", "kblockd", "irq/"}

func inTempDir(p string) bool {
	for _, d := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

func (c *collector) checkProcs() {
	badNames := map[string]bool{}
	for _, n := range c.rules.Procs {
		badNames[n] = true
	}
	for _, pid := range listPids() {
		if pid == c.selfP {
			continue
		}
		p, ok := readProc(pid)
		if !ok || (p.exe == "" && p.cmd == "") {
			continue // kernel thread or gone
		}
		exe := strings.TrimSuffix(p.exe, " (deleted)")
		argv0 := ""
		if f := strings.Fields(p.cmd); len(f) > 0 {
			argv0 = filepath.Base(f[0])
		}
		detail := fmt.Sprintf("pid=%d ppid=%d uid=%d comm=%s exe=%s cmd=%s", p.pid, p.ppid, p.uid, p.comm, p.exe, p.cmd)
		key := fmt.Sprintf("pid:%d:%s", p.pid, p.comm)
		switch {
		case strings.HasPrefix(p.exe, "/memfd:"):
			c.add("procs", key, snapshot.Crit, "process running from memory (memfd, fileless)", detail, "")
		case strings.HasSuffix(p.exe, " (deleted)"):
			c.add("procs", key, snapshot.Crit, "running binary was deleted (implant cleanup, or a daemon not restarted after reinstall)", detail, "")
		case inTempDir(exe):
			c.add("procs", key, snapshot.Crit, "process running from a temp dir", detail, "")
		case badNames[p.comm] || badNames[argv0] || badNames[filepath.Base(exe)]:
			c.add("procs", key, snapshot.Crit, "process name from known red team kit", detail, "")
		case p.exe != "" && looksKthread(p.comm, p.cmd):
			c.add("procs", key, snapshot.Crit, "userspace process disguised as a kernel thread", detail, "")
		case !p.foreignMountNS && p.exe != "" && c.owned != nil && !c.isOwned(exe) && exe != c.self:
			c.add("procs", "unowned:"+exe, snapshot.Warn, "process running a binary no package owns", detail, exe)
		}
		if env, err := readLimited(fmt.Sprintf("/proc/%d/environ", pid), 64<<10); err == nil {
			for _, kv := range strings.Split(string(env), "\x00") {
				if strings.HasPrefix(kv, "LD_PRELOAD=") || strings.HasPrefix(kv, "LD_AUDIT=") {
					c.add("procs", "env:"+key, snapshot.Crit, "process started with "+strings.SplitN(kv, "=", 2)[0], kv+"  "+detail, "")
				}
			}
		}
		if inTempDir(p.cwd + "/") {
			c.add("procs", "cwd:"+key, snapshot.Warn, "process working directory is a temp dir", p.cwd+"  "+detail, "")
		}
		if exe != "" && !p.foreignMountNS {
			// one stable info item per executable so diffs show new programs
			c.add("procs", "exe:"+exe, snapshot.Info, "running executable", truncate(p.cmd, 160), exe)
		}
	}
}

func looksKthread(comm, cmd string) bool {
	if strings.HasPrefix(cmd, "[") {
		return true
	}
	for _, k := range kthreadNames {
		if strings.HasPrefix(comm, k) || strings.HasPrefix(cmd, k) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// --- network --------------------------------------------------------------

type sockOwner struct {
	pid  int
	comm string
	exe  string
}

func socketOwners() map[string]sockOwner {
	out := map[string]sockOwner{}
	for _, pid := range listPids() {
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		var comm, exe string
		for _, fd := range fds {
			t, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
			if err != nil || !strings.HasPrefix(t, "socket:[") {
				continue
			}
			if comm == "" {
				comm = readTrim(fmt.Sprintf("/proc/%d/comm", pid))
				exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			}
			ino := strings.TrimSuffix(strings.TrimPrefix(t, "socket:["), "]")
			if _, ok := out[ino]; !ok {
				out[ino] = sockOwner{pid, comm, exe}
			}
		}
	}
	return out
}

func parseHexAddr(s string) (net.IP, int) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0
	}
	p, _ := strconv.ParseUint(port, 16, 16)
	b, err := hex.DecodeString(host)
	if err != nil {
		return nil, 0
	}
	// /proc/net stores each 32-bit word in host (little-endian) order.
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b), int(p)
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isInternal(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || cgnat.Contains(ip)
}

func (c *collector) checkNet() {
	owners := socketOwners()
	badIP := map[string]bool{}
	for _, ip := range c.rules.IPs {
		badIP[ip] = true
	}
	who := func(ino string) string {
		if o, ok := owners[ino]; ok {
			return fmt.Sprintf("%s(%d) %s", o.comm, o.pid, o.exe)
		}
		return "?"
	}
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6", "raw", "raw6"} {
		f, err := os.Open("/proc/net/" + proto)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan()
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 10 {
				continue
			}
			lip, lport := parseHexAddr(fl[1])
			rip, rport := parseHexAddr(fl[2])
			st, ino := fl[3], fl[9]
			if lip == nil || rip == nil {
				continue
			}
			base := strings.TrimSuffix(proto, "6")
			w := who(ino)
			switch {
			case strings.HasPrefix(proto, "raw"):
				c.add("net", "raw:"+w, snapshot.Warn, "raw socket open (sniffer/backdoor pattern)", fmt.Sprintf("%s %s", proto, w), "")
			case base == "tcp" && st == "0A", base == "udp" && st == "07" && rport == 0:
				comm := "?"
				if o, ok := owners[ino]; ok {
					comm = o.comm
				}
				key := fmt.Sprintf("listen:%s/%d:%s", base, lport, scopeOf(lip))
				c.add("net", key, snapshot.Info, fmt.Sprintf("listening %s/%d", base, lport), fmt.Sprintf("%s:%d %s", lip, lport, w), base+comm)
			case base == "tcp" && st == "01", base == "udp" && rport != 0:
				r := rip.String()
				if v4 := rip.To4(); v4 != nil {
					r = v4.String()
				}
				switch {
				case badIP[r]:
					c.add("net", "conn:"+r+":"+w, snapshot.Crit, "connection to known red team C2/attacker", fmt.Sprintf("%s:%d -> %s:%d %s", lip, lport, r, rport, w), "")
				case !isInternal(rip):
					c.add("net", "conn:"+r+":"+w, snapshot.Warn, "connection to a public address", fmt.Sprintf("%s:%d -> %s:%d %s", lip, lport, r, rport, w), "")
				}
			}
		}
		f.Close()
	}

	if f, err := os.Open("/proc/net/packet"); err == nil {
		sc := bufio.NewScanner(f)
		sc.Scan()
		benign := map[string]bool{"dhclient": true, "dhcpcd": true, "NetworkManager": true, "systemd-network": true, "lldpd": true, "wpa_supplicant": true, "dhcpd": true, "keepalived": true}
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 9 {
				continue
			}
			ino := fl[len(fl)-1]
			o := owners[ino]
			sev := snapshot.Warn
			if benign[o.comm] || o.comm == "" {
				// no owner visible means another namespace or the kernel
				sev = snapshot.Info
			}
			c.add("net", "packet:"+o.comm+":"+o.exe, sev, "AF_PACKET socket (magic-packet backdoors listen this way)", who(ino), "")
		}
		f.Close()
	}

	for _, d := range globAll("/sys/class/net/*") {
		fl := readTrim(d + "/flags")
		v, err := strconv.ParseUint(strings.TrimPrefix(fl, "0x"), 16, 32)
		if err == nil && v&0x100 != 0 {
			c.add("net", "promisc:"+filepath.Base(d), snapshot.Warn, "interface in promiscuous mode", filepath.Base(d), "")
		}
	}

	for _, tool := range [][]string{{"nft", "list", "ruleset"}, {"iptables-save"}} {
		out, err := runCmd(10*time.Second, tool[0], tool[1:]...)
		if err == nil && len(out) > 0 {
			c.add("net", "firewall:"+tool[0], snapshot.Info, "firewall ruleset", fmt.Sprintf("%d lines", strings.Count(string(out), "\n")), sha256Bytes(out))
		}
	}
}

func scopeOf(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "any"
	case ip.IsLoopback():
		return "lo"
	default:
		return ip.String()
	}
}

// --- kernel and logs ------------------------------------------------------

func (c *collector) checkKernel() {
	if b, err := os.ReadFile("/proc/modules"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) == 0 {
				continue
			}
			taint := ""
			if i := strings.LastIndex(l, "("); i >= 0 && strings.HasSuffix(l, ")") {
				taint = l[i:]
			}
			sev, msg := snapshot.Info, "kernel module"
			if strings.ContainsAny(taint, "OE") {
				sev, msg = snapshot.Warn, "out-of-tree or unsigned kernel module "+taint
			}
			c.add("kernel", "mod:"+f[0], sev, msg, f[0]+" "+taint, f[0])
		}
	}
	if t := readTrim("/proc/sys/kernel/tainted"); t != "" && t != "0" {
		c.add("kernel", "tainted", snapshot.Info, "kernel taint flags", t, "")
	}
	_ = filepath.WalkDir("/sys/fs/bpf", func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		c.add("kernel", "bpf:"+p, snapshot.Warn, "pinned BPF object (tc/XDP backdoors pin maps here)", p, "")
		return nil
	})
}

func (c *collector) checkLogs() {
	for _, p := range []string{"/var/log/wtmp", "/var/log/btmp", "/var/log/auth.log", "/var/log/secure", "/var/log/messages", "/var/log/syslog", "/var/log/audit/audit.log"} {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.Size() == 0 {
			c.add("logs", "empty:"+p, snapshot.Warn, "log file is empty (wiped?)", p, "")
		}
		if t, err := os.Readlink(p); err == nil && t == "/dev/null" {
			c.add("logs", "devnull:"+p, snapshot.Crit, "log file symlinked to /dev/null", p, "")
		}
	}
	if !exists("/var/log/journal") {
		c.add("logs", "journal", snapshot.Info, "journald is not persistent (logs vanish on reboot)", "", "")
	}
}
