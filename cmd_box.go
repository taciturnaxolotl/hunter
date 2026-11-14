package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"

	"github.com/taciturnaxolotl/hunter/internal/remote"
	"github.com/taciturnaxolotl/hunter/internal/report"
	"github.com/taciturnaxolotl/hunter/internal/sanitize"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"github.com/taciturnaxolotl/hunter/internal/sweep"
	"github.com/taciturnaxolotl/hunter/internal/target"
	"github.com/taciturnaxolotl/hunter/internal/tui"
	"github.com/taciturnaxolotl/hunter/rules"
)

// localRuns is where scans of the box hunter is running on are kept, so a
// second scan has something to diff against without any piping.
func localRuns() string {
	if d := os.Getenv("HUNTER_RUNS"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/root"
	}
	return filepath.Join(home, ".hunter")
}

func quarantineDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/root"
	}
	return filepath.Join(home, ".quarantine")
}

// ownDirs is hunter's state on a box. Collect never walks it: saved scans
// and quarantined implants would match every indicator again.
func ownDirs(extra ...string) []string {
	dirs := []string{localRuns(), quarantineDir()}
	for _, d := range extra {
		if abs, err := filepath.Abs(d); err == nil {
			dirs = append(dirs, abs)
		}
	}
	return dirs
}

// allowFile is this box's allow list, written by the fix walkthrough and
// read by every scan and collect on the box.
func allowFile() string { return filepath.Join(localRuns(), "allow.json") }

// localRules returns the box's allow list as an extra rules pack, if any.
func localRules() []string {
	b, err := os.ReadFile(allowFile())
	if err != nil {
		return nil
	}
	return []string{string(b)}
}

// allow adds patterns to the box's allow list.
func allow(patterns ...string) error {
	pack := rules.Rules{Name: "allowed-on-this-box"}
	if b, err := os.ReadFile(allowFile()); err == nil {
		if err := json.Unmarshal(b, &pack); err != nil {
			return fmt.Errorf("%s: %w", allowFile(), err)
		}
	}
	for _, p := range patterns {
		if !slices.Contains(pack.Allow, p) {
			pack.Allow = append(pack.Allow, p)
		}
	}
	b, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(localRuns(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(allowFile(), append(b, '\n'), 0o600)
}

func localHost() remote.Host {
	name, _ := os.Hostname()
	if name == "" {
		name = "localhost"
	}
	return remote.Host{Name: name}
}

func scanCmd() *cobra.Command {
	var (
		o         = target.Options{Version: version}
		runs      string
		ruleFiles []string
		sevS      string
		rebase    bool
		watch     time.Duration
		plain     bool
		agent     bool
		max       int
	)
	c := &cobra.Command{
		Use:   "scan",
		Short: "Hunt on this box: scan, save, and diff against the last baseline",
		Long: "Scan the box hunter is running on. Every scan is saved under --runs; the first\n" +
			"becomes the baseline and later scans show what changed. In a terminal this opens\n" +
			"a pager with changes and findings, rescans on --watch, and hands off to the fix\n" +
			"walkthrough (the same as running quarantine with no paths).",
		Example: "  sudo ./hunter scan\n  sudo ./hunter scan --watch 5m\n  sudo ./hunter scan --plain --sev crit",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sev, err := snapshot.ParseSev(sevS)
			if err != nil {
				return err
			}
			for _, f := range ruleFiles {
				b, err := os.ReadFile(f)
				if err != nil {
					return err
				}
				o.Rules = append(o.Rules, string(b))
			}
			o.Rules = append(o.Rules, localRules()...)
			if os.Geteuid() != 0 {
				logger.Warn("not running as root; much of /proc and /etc will be unreadable")
			}
			st := snapshot.Store(runs)
			host := localHost()
			o.SkipDirs = ownDirs(runs)
			// the timestomp window follows the baseline unless asked otherwise
			since := o.Since
			collect := func() (*snapshot.Snapshot, error) {
				opts := o
				if since == 0 {
					opts.Since = 24 * time.Hour
					if base, err := st.Baseline(host.Name); err == nil {
						opts.Since = time.Since(base.Time) + 15*time.Minute
					}
				}
				return target.Collect(opts)
			}
			if !agent && !plain && isTerminal(os.Stdout) && isTerminal(os.Stdin) {
				return scanTUI(tui.ScanConfig{
					Host: host, Store: st, Collect: collect, Rebase: rebase, Watch: watch, Sev: sev,
					Fix: func() *exec.Cmd {
						exe, _ := os.Executable()
						fix := exec.Command(exe, "quarantine", "--runs", runs, "--sev", sevS)
						fix.Stdin, fix.Stdout, fix.Stderr = os.Stdin, os.Stdout, os.Stderr
						return fix
					},
				}, max)
			}
			rep := reporter(agent, max)
			ctx := cmd.Context()
			for round := 1; ; round++ {
				base, _ := st.Baseline(host.Name)
				snap, err := collect()
				if err != nil {
					return err
				}
				rep.SweepHost(sweep.Record(st, host, snap, base, rebase && round == 1))
				if watch <= 0 {
					return nil
				}
				logger.Info("waiting for next scan", "in", watch)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(watch):
				}
			}
		},
	}
	f := c.Flags()
	f.StringVar(&runs, "runs", localRuns(), "where scans and the baseline are kept ($HUNTER_RUNS)")
	f.StringVar(&sevS, "sev", "warn", "lowest severity shown in findings: info, warn, crit")
	f.BoolVar(&rebase, "baseline", false, "make this scan the new baseline")
	f.DurationVar(&watch, "watch", 0, "scan again every interval (e.g. 5m)")
	f.BoolVar(&plain, "plain", false, "print the report instead of opening the pager")
	f.BoolVar(&agent, "agent", false, "print sanitized JSON lines for a model")
	f.IntVar(&max, "max", 0, "max lines in the printed report (0 = all)")
	f.DurationVar(&o.Since, "since", 0, "timestomp window (default: time since baseline, else 24h)")
	f.BoolVar(&o.PkgVerify, "pkg", true, "verify installed packages (rpm -Va / dpkg --verify / pacman -Qkk)")
	f.DurationVar(&o.PkgTimeout, "pkg-timeout", 4*time.Minute, "package verify timeout")
	f.StringArrayVar(&ruleFiles, "rules", nil, "extra indicator pack file (repeatable)")
	return c
}

func scanTUI(cfg tui.ScanConfig, max int) error {
	m := tui.NewScan(cfg)
	if _, err := tea.NewProgram(m).Run(); err != nil {
		return err
	}
	if r := m.Result(); r != nil {
		report.Human{W: os.Stdout, Max: max}.SweepHost(*r)
	}
	return nil
}

// fixWalkthrough steps through every actionable finding in the latest
// scan of this box, one at a time, and does only what is chosen.
func fixWalkthrough(runs string, sev snapshot.Sev, dir string) error {
	if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		return errors.New("the fix walkthrough needs a terminal; run it on the box, or pass paths to quarantine")
	}
	host := localHost()
	snap, err := snapshot.Store(runs).Latest(host.Name)
	if err != nil {
		return fmt.Errorf("no scan of this box yet (%w); run hunter scan first", err)
	}
	steps := target.Steps(snap.Filter(sev, ""))
	if len(steps) == 0 {
		lipgloss.Println(report.Green.Render("nothing actionable at or above " + sev.String()))
		return nil
	}
	lipgloss.Println(report.Dim.Render("reading the package database so packaged files are never quarantined..."))
	owned := target.Ownership()
	lipgloss.Printf("%s %d things to look at from the %s scan. Nothing changes unless you pick it.\n\n",
		report.Bold.Render("fix"), len(steps), snap.Time.Local().Format("15:04:05"))

	var done []string
	for i, st := range steps {
		lipgloss.Println(stepHeader(i+1, len(steps), st))
		act, err := stepLoop(st, owned, dir)
		if err != nil {
			return err
		}
		if act == "stop" {
			break
		}
		if act != "" && act != "skip" {
			done = append(done, act)
		}
		fmt.Println()
	}
	if len(done) == 0 {
		lipgloss.Println(report.Dim.Render("no changes made"))
		return nil
	}
	lipgloss.Println(report.Bold.Render("done:"))
	for _, d := range done {
		fmt.Println("  " + d)
	}
	lipgloss.Println(report.Dim.Render("scan again to confirm; anything quarantined is in " + dir))
	return nil
}

func stepHeader(n, total int, st target.Step) string {
	what := st.Path
	if what == "" && len(st.Procs) == 0 {
		what = st.Obs[0].Check + " " + st.Obs[0].Key
	} else if what == "" {
		var ps []string
		for _, p := range st.Procs {
			ps = append(ps, fmt.Sprintf("pid %d (%s)", p.PID, sanitize.Clean(p.Comm, 30)))
		}
		what = strings.Join(ps, ", ")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\n", report.Dim.Render(fmt.Sprintf("[%d/%d]", n, total)), report.SevTag(st.Sev()), report.Bold.Render(sanitize.Clean(what, 200)))
	for _, o := range st.Obs {
		fmt.Fprintf(&b, "  %s %-8s %s\n", report.SevTag(o.Sev), o.Check, sanitize.Clean(o.Msg, 120))
		if o.Detail != "" {
			fmt.Fprintf(&b, "           %s\n", report.Dim.Render(sanitize.Clean(o.Detail, 200)))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// stepLoop offers the actions that make sense for one step until one is
// taken (inspect does not count) and returns a line describing it.
func stepLoop(st target.Step, owned func(string) bool, dir string) (string, error) {
	for {
		procs := liveProcs(st)
		why := ""
		if st.Path != "" {
			why = target.WhyNotQuarantine(st.Path, owned)
		}
		opts := []huh.Option[string]{huh.NewOption("skip", "skip")}
		if st.Path != "" && why != "gone already" {
			opts = append(opts, huh.NewOption("inspect "+st.Path, "inspect"))
		}
		if len(procs) > 0 {
			opts = append(opts, huh.NewOption(fmt.Sprintf("kill %s", procList(procs)), "kill"))
		}
		if st.Path != "" && why == "" {
			label := "quarantine " + st.Path
			if len(procs) > 0 {
				label = "kill " + procList(procs) + ", then quarantine " + st.Path
			}
			opts = append(opts, huh.NewOption(label, "quarantine"))
		}
		if st.Path != "" && target.Editable(st.Path) {
			opts = append(opts, huh.NewOption("edit "+st.Path+" in "+editor(), "edit"))
		}
		var keys []string
		for _, o := range st.Obs {
			keys = append(keys, target.AllowKey(o))
		}
		opts = append(opts,
			huh.NewOption("known-good: allow "+strings.Join(keys, ", ")+" on this box", "allow"),
			huh.NewOption("stop here", "stop"))

		desc := ""
		if why != "" {
			desc = "not offering quarantine: " + why
		}
		choice := "skip"
		if err := huh.NewSelect[string]().Title("what now?").Description(desc).Options(opts...).Value(&choice).Run(); err != nil {
			if errors.Is(err, huh.ErrUserAborted) {
				return "stop", nil
			}
			return "", err
		}

		switch choice {
		case "inspect":
			if err := target.Inspect(os.Stdout, []string{st.Path}, 20); err != nil {
				lipgloss.Println(report.Red.Render(err.Error()))
			}
			continue
		case "kill":
			var killed []string
			for _, p := range procs {
				if err := target.Kill(p); err != nil {
					lipgloss.Println(report.Red.Render(err.Error()))
					continue
				}
				killed = append(killed, strconv.Itoa(p.PID))
			}
			if len(killed) == 0 {
				continue
			}
			return "killed pid " + strings.Join(killed, ", "), nil
		case "quarantine":
			for _, p := range procs {
				if err := target.Kill(p); err != nil {
					lipgloss.Println(report.Red.Render(err.Error()))
				}
			}
			if err := target.Quarantine(os.Stdout, []string{st.Path}, dir, true); err != nil {
				lipgloss.Println(report.Red.Render(err.Error()))
				continue
			}
			return "quarantined " + st.Path, nil
		case "allow":
			if err := allow(keys...); err != nil {
				lipgloss.Println(report.Red.Render(err.Error()))
				continue
			}
			return "allowed " + strings.Join(keys, ", ") + " (in " + allowFile() + ")", nil
		case "edit":
			ed := exec.Command(editor(), st.Path)
			ed.Stdin, ed.Stdout, ed.Stderr = os.Stdin, os.Stdout, os.Stderr
			if err := ed.Run(); err != nil {
				lipgloss.Println(report.Red.Render(err.Error()))
				continue
			}
			return "edited " + st.Path, nil
		default:
			return choice, nil
		}
	}
}

// liveProcs is the step's processes that still exist, plus anything now
// running its file.
func liveProcs(st target.Step) []target.Proc {
	var out []target.Proc
	seen := map[int]bool{}
	for _, p := range st.Procs {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", p.PID)); err == nil {
			out = append(out, p)
			seen[p.PID] = true
		}
	}
	if st.Path != "" {
		for _, pid := range target.Running(st.Path) {
			if !seen[pid] {
				comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
				out = append(out, target.Proc{PID: pid, Comm: strings.TrimSpace(string(comm))})
			}
		}
	}
	return out
}

func procList(ps []target.Proc) string {
	var s []string
	for _, p := range ps {
		s = append(s, fmt.Sprintf("%d (%s)", p.PID, sanitize.Clean(p.Comm, 20)))
	}
	return "pid " + strings.Join(s, ", ")
}

func editor() string {
	for _, v := range []string{"VISUAL", "EDITOR"} {
		if e := os.Getenv(v); e != "" {
			return e
		}
	}
	for _, e := range []string{"vim", "vi", "nano"} {
		if _, err := exec.LookPath(e); err == nil {
			return e
		}
	}
	return "vi"
}
