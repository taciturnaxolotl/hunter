//go:build linux

package target

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/taciturnaxolotl/hunter/internal/sanitize"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

func pidsRunning(path string) []int {
	var out []int
	for _, pid := range listPids() {
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			continue
		}
		if strings.TrimSuffix(exe, " (deleted)") == path {
			out = append(out, pid)
		}
	}
	return out
}

type quarantineRecord struct {
	Time   string `json:"time"`
	Path   string `json:"path"`
	Stored string `json:"stored"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mtime  string `json:"mtime"`
	Ctime  string `json:"ctime"`
	Magic  string `json:"magic"`
	Killed []int  `json:"killed,omitempty"`
}

// Quarantine moves each path into dir (chmod 0, original metadata kept in
// MANIFEST.jsonl), optionally SIGKILLing whatever is running it first.
func Quarantine(w io.Writer, paths []string, dir string, kill bool) error {
	if len(paths) == 0 {
		return errors.New("no paths given")
	}
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".quarantine")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	manifest, err := os.OpenFile(filepath.Join(dir, "MANIFEST.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer manifest.Close()
	failed := 0
	for _, p := range paths {
		p, _ = filepath.Abs(p)
		rec, err := quarantineOne(p, dir, kill)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", p, err)
			failed++
			continue
		}
		b, _ := json.Marshal(rec)
		manifest.Write(append(b, '\n'))
		fmt.Fprintf(w, "quarantined %s -> %s sha256=%s killed=%v\n", rec.Path, rec.Stored, rec.SHA256, rec.Killed)
	}
	if failed > 0 {
		return fmt.Errorf("%d paths failed", failed)
	}
	return nil
}

func quarantineOne(p, dir string, kill bool) (*quarantineRecord, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, errors.New("is a directory; quarantine the files inside it")
	}
	mtime, ctime := fileTimes(fi)
	uid, gid := fileOwner(fi)
	rec := &quarantineRecord{
		Time: time.Now().UTC().Format(time.RFC3339), Path: p, Size: fi.Size(), Mode: fi.Mode().String(),
		UID: uid, GID: gid, Mtime: mtime.UTC().Format(time.RFC3339), Ctime: ctime.UTC().Format(time.RFC3339),
	}
	if fi.Mode().IsRegular() {
		rec.SHA256 = sha256File(p)
		rec.Magic = fmt.Sprintf("%x", readHead(p, 16))
	}
	if kill {
		for _, pid := range pidsRunning(p) {
			if syscall.Kill(pid, syscall.SIGKILL) == nil {
				rec.Killed = append(rec.Killed, pid)
			}
		}
	}
	_ = clearImmutable(p)
	_ = clearImmutable(filepath.Dir(p))
	flat := strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", "_")
	dest := filepath.Join(dir, time.Now().UTC().Format("20060102T150405Z")+"_"+flat)
	if err := os.Rename(p, dest); err != nil {
		var le *os.LinkError
		if !errors.As(err, &le) || !errors.Is(le.Err, syscall.EXDEV) {
			return nil, err
		}
		if err := copyFile(p, dest); err != nil {
			return nil, err
		}
		if err := os.Remove(p); err != nil {
			return nil, err
		}
	}
	_ = os.Chmod(dest, 0)
	rec.Stored = dest
	return rec, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

var interesting = regexp.MustCompile(`(\b\d{1,3}(\.\d{1,3}){3}\b|https?://|/(tmp|etc|usr|var|dev|proc|bin|lib)[/A-Za-z0-9._-]*|\.so\b|passw|LD_|socket|exec|/bin/sh|bash|ssh|pam_|key|token|beacon|c2|callback)`)

// Inspect prints stat, hashes, chattr flags, capabilities, ELF facts and
// the most interesting strings of each path.
func Inspect(w io.Writer, paths []string, nStrings int) error {
	if len(paths) == 0 {
		return errors.New("no paths given")
	}
	for _, p := range paths {
		fmt.Fprintln(w, "== "+sanitize.Clean(p, 300))
		fi, err := os.Lstat(p)
		if err != nil {
			fmt.Fprintln(w, "  error:", err)
			continue
		}
		mtime, ctime := fileTimes(fi)
		uid, gid := fileOwner(fi)
		fmt.Fprintf(w, "  mode=%s uid=%d gid=%d size=%d\n  mtime=%s ctime=%s\n", fi.Mode(), uid, gid, fi.Size(),
			mtime.UTC().Format(time.RFC3339), ctime.UTC().Format(time.RFC3339))
		if fi.Mode()&os.ModeSymlink != 0 {
			t, _ := os.Readlink(p)
			fmt.Fprintln(w, "  symlink ->", sanitize.Clean(t, 300))
			continue
		}
		if !fi.Mode().IsRegular() {
			continue
		}
		fmt.Fprintln(w, "  sha256="+sha256File(p))
		if flags, err := fsFlags(p); err == nil && flags&(fsImmutableFl|fsAppendFl) != 0 {
			fmt.Fprintln(w, "  chattr:", flagString(flags))
		}
		if caps := fileCaps(p); len(caps) > 0 {
			fmt.Fprintln(w, "  caps:", strings.Join(caps, ","))
		}
		if pids := pidsRunning(p); len(pids) > 0 {
			fmt.Fprintln(w, "  running as pids:", pids)
		}
		b, _ := readLimited(p, 32<<20)
		if isELF(b) {
			if f, err := elf.NewFile(bytes.NewReader(b)); err == nil {
				static := true
				for _, prog := range f.Progs {
					if prog.Type == elf.PT_INTERP {
						static = false
					}
				}
				libs, _ := f.ImportedLibraries()
				fmt.Fprintf(w, "  elf: %s %s static=%v libs=%v\n", f.Machine, f.Type, static, libs)
			}
			if bytes.Contains(b[:min(len(b), 4096)], []byte("UPX!")) {
				fmt.Fprintln(w, "  packed: UPX")
			}
		}
		shown := 0
		for _, s := range printableStrings(b, 6, 0) {
			if shown >= nStrings {
				break
			}
			if interesting.MatchString(s) || !isELF(b) {
				fmt.Fprintln(w, "  | "+sanitize.Clean(s, 200))
				shown++
			}
		}
	}
	return nil
}

// Ownership reads the package databases once and reports whether a
// package claims a file. It returns nil when ownership cannot be known.
func Ownership() func(string) bool {
	c := &collector{res: dirResolver{}}
	c.loadOwnership()
	if c.owned == nil {
		return nil
	}
	return c.isOwned
}

// Running lists the processes executing path.
func Running(path string) []int { return pidsRunning(path) }

// Kill SIGKILLs pid, but only if it is still the process the snapshot
// saw: pids get reused, and the snapshot may be minutes old.
func Kill(p Proc) error {
	if p.Comm != "" {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", p.PID))
		if err != nil {
			return fmt.Errorf("pid %d is gone", p.PID)
		}
		if got := strings.TrimSpace(string(b)); got != p.Comm {
			return fmt.Errorf("pid %d is now %q, not %q; not killing it", p.PID, got, p.Comm)
		}
	}
	return syscall.Kill(p.PID, syscall.SIGKILL)
}
