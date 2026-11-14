// Package remote gets hunter onto a box and runs it there: no scp, no
// sftp-server, nothing typed on a console, just one SSH session that
// streams the static binary over stdin and removes it afterwards.
package remote

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Host is one SSH destination plus the name its sweeps are filed under.
type Host struct {
	User, Addr, Port, Name string
}

func (h Host) dest() string {
	if h.User != "" {
		return h.User + "@" + h.Addr
	}
	return h.Addr
}

// ParseHost reads [user@]host[:port]. An empty name defaults to the host
// (plus _port when one is given).
func ParseHost(spec, name, defUser string) Host {
	h := Host{User: defUser, Name: name}
	if u, rest, ok := strings.Cut(spec, "@"); ok {
		h.User, spec = u, rest
	}
	if strings.Count(spec, ":") == 1 {
		addr, port, _ := strings.Cut(spec, ":")
		spec, h.Port = addr, port
	}
	h.Addr = spec
	if h.Name == "" {
		h.Name = h.Addr
		if h.Port != "" {
			h.Name += "_" + h.Port
		}
	}
	return h
}

// ReadHosts parses a hosts file: one `target [name]` per line, # comments.
func ReadHosts(path, defUser string) ([]Host, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Host
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := ""
		if len(fields) > 1 {
			name = fields[1]
		}
		out = append(out, ParseHost(fields[0], name, defUser))
	}
	return out, sc.Err()
}

// Options are the SSH knobs shared by every laptop-side command.
type Options struct {
	User        string
	Identity    string
	SSHOpts     []string
	Sudo        bool
	Interactive bool
	BinDir      string
}

func (o *Options) sshArgs(h Host) []string {
	args := []string{"-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new", "-o", "ServerAliveInterval=15", "-o", "LogLevel=ERROR"}
	if !o.Interactive {
		args = append(args, "-o", "BatchMode=yes")
	}
	if o.Identity != "" {
		args = append(args, "-i", o.Identity)
	}
	if h.Port != "" {
		args = append(args, "-p", h.Port)
	}
	for _, opt := range o.SSHOpts {
		args = append(args, "-o", opt)
	}
	return append(args, h.dest())
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

var archCache sync.Map

var unameArch = map[string]string{
	"x86_64": "amd64", "amd64": "amd64",
	"aarch64": "arm64", "arm64": "arm64",
	"i686": "386", "i386": "386",
	"armv7l": "arm", "armv6l": "arm",
	"riscv64": "riscv64",
	"ppc64le": "ppc64le",
	"s390x":   "s390x",
}

func (o *Options) arch(ctx context.Context, h Host) (string, error) {
	key := h.dest() + ":" + h.Port
	if v, ok := archCache.Load(key); ok {
		return v.(string), nil
	}
	out, err := exec.CommandContext(ctx, "ssh", append(o.sshArgs(h), "uname -m")...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			msg := strings.TrimSpace(string(ee.Stderr))
			if !strings.HasPrefix(msg, "ssh:") {
				msg = "ssh: " + msg
			}
			return "", errors.New(msg)
		}
		return "", fmt.Errorf("ssh: %w", err)
	}
	m := strings.TrimSpace(string(out))
	arch := unameArch[m]
	if arch == "" {
		return "", fmt.Errorf("unsupported target arch %q", m)
	}
	archCache.Store(key, arch)
	return arch, nil
}

type binary struct {
	data []byte
	sha  string
}

var binCache sync.Map

func (o *Options) binary(arch string) (*binary, error) {
	if v, ok := binCache.Load(arch); ok {
		return v.(*binary), nil
	}
	name := "hunter-linux-" + arch
	var cands []string
	if o.BinDir != "" {
		cands = append(cands, filepath.Join(o.BinDir, name))
	}
	if exe, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Join(filepath.Dir(exe), name))
		if runtime.GOOS == "linux" && runtime.GOARCH == arch {
			cands = append(cands, exe)
		}
	}
	cands = append(cands, filepath.Join("dist", name))
	for _, p := range cands {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		bin := &binary{data: b, sha: sha256Hex(b)}
		binCache.Store(arch, bin)
		return bin, nil
	}
	return nil, fmt.Errorf("no %s found (run build.sh, or pass --bin-dir)", name)
}

// Phase is how far a Run has got, for progress displays.
type Phase int

const (
	Connecting Phase = iota // probing the architecture
	Running                 // binary streamed, subcommand running
)

// Run streams the right static binary to h, runs one hunter subcommand
// there, and removes the binary. The binary refuses to run if its own
// sha256 does not match what was sent (see VerifySelf). progress may be nil.
func (o *Options) Run(ctx context.Context, h Host, sub []string, stdout, stderr io.Writer, progress func(Phase)) error {
	if progress == nil {
		progress = func(Phase) {}
	}
	progress(Connecting)
	arch, err := o.arch(ctx, h)
	if err != nil {
		return err
	}
	bin, err := o.binary(arch)
	if err != nil {
		return err
	}
	q := make([]string, len(sub))
	for i, a := range sub {
		q[i] = shQuote(a)
	}
	run := "env " + shaEnv + "=" + bin.sha + ` "$P" ` + strings.Join(q, " ")
	if o.Sudo {
		run = "sudo -n " + run
	}
	script := `umask 077; P="${HOME:-/root}/.hunter.$$"; cat > "$P" && chmod 700 "$P" && ` + run + `; rc=$?; rm -f "$P"; exit $rc`
	cmd := exec.CommandContext(ctx, "ssh", append(o.sshArgs(h), "sh -c "+shQuote(script))...)
	cmd.Stdin = bytes.NewReader(bin.data)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	progress(Running)
	return cmd.Run()
}

const shaEnv = "HUNTER_SHA"

// VerifySelf is the target half of the transfer check: when the laptop
// said what it sent, make sure that is what is running.
func VerifySelf() error {
	want := os.Getenv(shaEnv)
	if want == "" {
		return nil
	}
	p := "/proc/self/exe"
	if _, err := os.Stat(p); err != nil {
		if p, err = os.Executable(); err != nil {
			return err
		}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if got := sha256Hex(b); !strings.EqualFold(got, want) {
		return fmt.Errorf("hunter on target does not match what was sent (got %s want %s): transfer corrupted or tampered", got, want)
	}
	return nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
