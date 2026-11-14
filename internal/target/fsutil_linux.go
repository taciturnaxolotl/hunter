//go:build linux

package target

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const maxHashBytes = 64 << 20

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxHashBytes)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sha256Bytes(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

func readHead(path string, n int) []byte {
	b, _ := readLimited(path, int64(n))
	return b
}

func isELF(head []byte) bool { return bytes.HasPrefix(head, []byte("\x7fELF")) }

func fileTimes(fi os.FileInfo) (mtime, ctime time.Time) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fi.ModTime(), fi.ModTime()
	}
	return time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)), time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))
}

func fileOwner(fi os.FileInfo) (uid, gid uint32) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid, st.Gid
	}
	return 0, 0
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

const (
	fsIocGetflags = 0x80086601
	fsIocSetflags = 0x40086602
	fsImmutableFl = 0x10
	fsAppendFl    = 0x20
)

// fsFlags reads chattr flags directly so a trojaned lsattr cannot lie.
func fsFlags(path string) (int, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var flags int
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocGetflags, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return 0, errno
	}
	return flags, nil
}

func clearImmutable(path string) error {
	flags, err := fsFlags(path)
	if err != nil {
		return err
	}
	if flags&(fsImmutableFl|fsAppendFl) == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	flags &^= fsImmutableFl | fsAppendFl
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocSetflags, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return errno
	}
	return nil
}

func flagString(flags int) string {
	var parts []string
	if flags&fsImmutableFl != 0 {
		parts = append(parts, "immutable")
	}
	if flags&fsAppendFl != 0 {
		parts = append(parts, "append-only")
	}
	return strings.Join(parts, ",")
}

var capNames = map[int]string{
	0: "chown", 1: "dac_override", 2: "dac_read_search", 3: "fowner", 4: "fsetid", 5: "kill",
	6: "setgid", 7: "setuid", 8: "setpcap", 10: "net_bind_service", 12: "net_admin", 13: "net_raw",
	16: "sys_module", 17: "sys_rawio", 18: "sys_chroot", 19: "sys_ptrace", 21: "sys_admin",
	25: "sys_time", 33: "audit_control", 38: "perfmon", 39: "bpf", 40: "checkpoint_restore",
}

var dangerousCaps = map[string]bool{
	"setuid": true, "setgid": true, "sys_admin": true, "dac_override": true, "dac_read_search": true,
	"sys_module": true, "sys_ptrace": true, "chown": true, "fowner": true, "setpcap": true, "bpf": true,
}

// fileCaps decodes the security.capability xattr (what getcap shows).
func fileCaps(path string) []string {
	buf := make([]byte, 64)
	n, err := syscall.Getxattr(path, "security.capability", buf)
	if err != nil || n < 12 {
		return nil
	}
	le := func(i int) uint64 {
		return uint64(buf[i]) | uint64(buf[i+1])<<8 | uint64(buf[i+2])<<16 | uint64(buf[i+3])<<24
	}
	perm := le(4)
	if n >= 20 {
		perm |= le(12) << 32
	}
	var out []string
	for bit := 0; bit < 64; bit++ {
		if perm&(1<<uint(bit)) == 0 {
			continue
		}
		if name, ok := capNames[bit]; ok {
			out = append(out, name)
		} else {
			out = append(out, "cap"+itoa(bit))
		}
	}
	if le(0)&1 != 0 {
		out = append(out, "+ep")
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}

// dirResolver resolves symlinked parent directories (merged /usr: /bin ->
// usr/bin) so package file lists and filesystem paths compare equal.
type dirResolver map[string]string

func (r dirResolver) norm(p string) string {
	dir, base := filepath.Split(p)
	dir = filepath.Clean(dir)
	res, ok := r[dir]
	if !ok {
		var err error
		res, err = filepath.EvalSymlinks(dir)
		if err != nil {
			res = dir
		}
		r[dir] = res
	}
	return filepath.Join(res, base)
}

func globAll(patterns ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range patterns {
		m, _ := filepath.Glob(p)
		for _, x := range m {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}

func isNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }

// printableStrings mimics strings(1) without trusting the box's copy.
func printableStrings(b []byte, min, max int) []string {
	var out []string
	start := -1
	for i := 0; i <= len(b); i++ {
		ok := i < len(b) && b[i] >= 0x20 && b[i] < 0x7f
		if ok && start < 0 {
			start = i
		}
		if !ok && start >= 0 {
			if i-start >= min {
				out = append(out, string(b[start:i]))
				if max > 0 && len(out) >= max {
					return out
				}
			}
			start = -1
		}
	}
	return out
}
