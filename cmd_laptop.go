package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"

	"github.com/taciturnaxolotl/hunter/internal/remote"
	"github.com/taciturnaxolotl/hunter/internal/report"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"github.com/taciturnaxolotl/hunter/internal/sweep"
	"github.com/taciturnaxolotl/hunter/internal/tui"
)

func sshFlags(c *cobra.Command, o *remote.Options) {
	f := c.Flags()
	f.StringVar(&o.User, "user", "root", "default SSH user for targets without user@")
	f.StringVarP(&o.Identity, "identity", "i", "", "identity file to authenticate with")
	f.StringArrayVarP(&o.SSHOpts, "ssh-option", "o", nil, "extra ssh -o option (repeatable), e.g. -o UserKnownHostsFile=/dev/null")
	f.BoolVar(&o.Sudo, "sudo", false, "run the target side through sudo -n (non-root user)")
	f.BoolVar(&o.Interactive, "interactive", false, "allow password prompts (disables BatchMode, sweeps one host at a time)")
	f.StringVar(&o.BinDir, "bin-dir", "", "directory holding hunter-linux-<arch> builds")
}

func runsFlag(c *cobra.Command, st *string) {
	c.Flags().StringVar(st, "runs", "runs", "where snapshots and baselines are kept")
}

func reporter(agent bool, max int) report.Reporter {
	if agent {
		return &report.Agent{W: os.Stdout}
	}
	return report.Human{W: os.Stdout, Max: max}
}

// confirm asks before something hard to undo. Without a terminal there is
// nobody to ask, so the caller must have passed --yes.
func confirm(yes bool, title, desc string) error {
	if yes {
		return nil
	}
	if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		return errors.New("refusing without confirmation; rerun with --yes")
	}
	ok := false
	if err := huh.NewConfirm().Title(title).Description(desc).Value(&ok).Run(); err != nil {
		return err
	}
	if !ok {
		return errors.New("cancelled")
	}
	return nil
}

func sweepCmd() *cobra.Command {
	var (
		o        sweep.Options
		runs     string
		hostFile string
		ruleFile []string
		max      int
		agent    bool
		plain    bool
		watch    time.Duration
	)
	c := &cobra.Command{
		Use:   "sweep [target...]",
		Short: "Push, collect and diff against each host's baseline",
		Long: "Sweep every host in parallel. The first sweep of a host becomes its baseline;\n" +
			"later sweeps print only what changed. Targets come from --hosts unless given as\n" +
			"arguments, each [user@]host[:port].",
		Example: "  hunter sweep\n  hunter sweep --watch 30m\n  hunter sweep -i lab.key root@127.0.0.1:2222",
		RunE: func(cmd *cobra.Command, args []string) error {
			hosts, err := targets(args, hostFile, o.SSH.User)
			if err != nil {
				return err
			}
			for _, f := range ruleFile {
				b, err := os.ReadFile(f)
				if err != nil {
					return err
				}
				o.Rules = append(o.Rules, string(b))
			}
			o.Store = snapshot.Store(runs)
			if o.SSH.Interactive {
				o.Jobs, plain = 1, true
			}
			ctx := cmd.Context()
			if !agent && !plain && isTerminal(os.Stdout) {
				return sweepTUI(ctx, &o, hosts, watch, max)
			}
			return sweepPlain(ctx, &o, hosts, watch, reporter(agent, max))
		},
	}
	sshFlags(c, &o.SSH)
	runsFlag(c, &runs)
	f := c.Flags()
	f.StringVar(&hostFile, "hosts", "hosts.txt", "hosts file, one target and optional name per line")
	f.IntVarP(&o.Jobs, "jobs", "j", 8, "hosts swept in parallel")
	f.BoolVar(&o.Rebase, "baseline", false, "make this sweep the new baseline for every host")
	f.IntVar(&max, "max", 40, "max lines printed per host (0 = all)")
	f.BoolVar(&agent, "agent", false, "print sanitized JSON lines for a model instead of the report")
	f.BoolVar(&plain, "plain", false, "print the report as hosts finish instead of the live view")
	f.DurationVar(&watch, "watch", 0, "sweep again every interval, forever (e.g. 30m)")
	f.DurationVar(&o.Since, "since", 0, "timestomp window (default: time since baseline, else 24h)")
	f.BoolVar(&o.PkgVerify, "pkg", true, "run rpm -Va / dpkg --verify / pacman -Qkk on targets")
	f.DurationVar(&o.PkgTimeout, "pkg-timeout", 4*time.Minute, "package verify timeout")
	f.StringArrayVar(&ruleFile, "rules", nil, "extra indicator pack JSON file (repeatable)")
	return c
}

func targets(args []string, hostFile, user string) ([]remote.Host, error) {
	var hosts []remote.Host
	if len(args) > 0 {
		for _, a := range args {
			hosts = append(hosts, remote.ParseHost(a, "", user))
		}
	} else {
		var err error
		if hosts, err = remote.ReadHosts(hostFile, user); err != nil {
			return nil, fmt.Errorf("%w (create a hosts file or pass targets)", err)
		}
	}
	if len(hosts) == 0 {
		return nil, errors.New("no targets")
	}
	return hosts, nil
}

func sweepPlain(ctx context.Context, o *sweep.Options, hosts []remote.Host, watch time.Duration, rep report.Reporter) error {
	for round := 1; ; round++ {
		start := time.Now()
		rep.SweepStart(round, len(hosts), start)
		results := sweep.Round(ctx, o, hosts, func(e sweep.Event) {
			if e.Phase == sweep.Done {
				rep.SweepHost(*e.Result)
			}
		})
		rep.SweepEnd(results, time.Since(start))
		if watch <= 0 || ctx.Err() != nil {
			return nil
		}
		logger.Info("waiting for next sweep", "in", watch, "at", time.Now().Add(watch).Format(time.Kitchen))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(watch):
		}
		o.Rebase = false
	}
}

// sweepTUI runs the live view, then leaves the full report of the last
// round in the scrollback.
func sweepTUI(ctx context.Context, o *sweep.Options, hosts []remote.Host, watch time.Duration, max int) error {
	m := tui.New(ctx, o, hosts, watch)
	if _, err := tea.NewProgram(m).Run(); err != nil {
		return err
	}
	results, took := m.Results()
	if len(results) == 0 {
		return nil
	}
	rep := report.Human{W: os.Stdout, Max: max}
	for _, r := range results {
		rep.SweepHost(r)
	}
	rep.SweepEnd(results, took)
	return nil
}

func showCmd() *cobra.Command {
	var (
		runs, sevS, check string
		max               int
		agent             bool
	)
	c := &cobra.Command{
		Use:     "show HOST|snapshot.json...",
		Short:   "Findings from the latest sweep",
		Example: "  hunter show --sev crit web\n  hunter show --check pam web db",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sev, err := snapshot.ParseSev(sevS)
			if err != nil {
				return err
			}
			st := snapshot.Store(runs)
			rep := reporter(agent, max)
			for _, a := range args {
				s, err := st.Resolve(a, "latest")
				if err != nil {
					return err
				}
				rep.Findings(a, s, s.Filter(sev, check))
			}
			return nil
		},
	}
	runsFlag(c, &runs)
	f := c.Flags()
	f.StringVar(&sevS, "sev", "warn", "minimum severity: info, warn, crit")
	f.StringVar(&check, "check", "", "only this check (accounts, fs, net, procs, ...)")
	f.IntVar(&max, "max", 0, "max findings (0 = all)")
	f.BoolVar(&agent, "agent", false, "sanitized JSON lines for a model")
	return c
}

func diffCmd() *cobra.Command {
	var (
		runs  string
		max   int
		agent bool
	)
	c := &cobra.Command{
		Use:   "diff HOST | OLD.json NEW.json",
		Short: "What changed between baseline and latest, or two snapshots",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st := snapshot.Store(runs)
			var old, cur *snapshot.Snapshot
			var err error
			name := args[len(args)-1]
			if len(args) == 1 {
				if old, err = st.Baseline(name); err != nil {
					return err
				}
				if cur, err = st.Latest(name); err != nil {
					return err
				}
			} else {
				if old, err = snapshot.Load(args[0]); err != nil {
					return err
				}
				if cur, err = snapshot.Load(args[1]); err != nil {
					return err
				}
			}
			reporter(agent, max).Diff(name, old, cur, snapshot.Diff(old, cur))
			return nil
		},
	}
	runsFlag(c, &runs)
	c.Flags().IntVar(&max, "max", 0, "max changes (0 = all)")
	c.Flags().BoolVar(&agent, "agent", false, "sanitized JSON lines for a model")
	return c
}

func baselineCmd() *cobra.Command {
	var (
		runs string
		yes  bool
	)
	c := &cobra.Command{
		Use:   "baseline HOST...",
		Short: "Accept the latest sweep as known-good",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st := snapshot.Store(runs)
			if !yes && isTerminal(os.Stdin) {
				if err := confirm(false, fmt.Sprintf("Accept the latest sweep of %d host(s) as known-good?", len(args)),
					"Anything red team left in place becomes invisible to later diffs."); err != nil {
					return err
				}
			}
			for _, h := range args {
				s, err := st.Promote(h)
				if err != nil {
					return err
				}
				lipgloss.Printf("%s baseline for %s is now the %s sweep\n", report.Green.Render("[+]"), h, s.Time.Local().Format("15:04:05"))
			}
			return nil
		},
	}
	runsFlag(c, &runs)
	c.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask")
	return c
}

func remoteCmd() *cobra.Command {
	var (
		o   remote.Options
		yes bool
	)
	c := &cobra.Command{
		Use:   "remote TARGET SUBCOMMAND [args...]",
		Short: "Run one target subcommand on one box",
		Example: "  hunter remote root@192.168.3.5 inspect /usr/sbin/rt-tagd\n" +
			"  hunter remote root@192.168.3.5 quarantine --kill /usr/sbin/rt-tagd",
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			h := remote.ParseHost(args[0], "", o.User)
			sub := args[1:]
			if sub[0] == "quarantine" {
				if err := confirm(yes, "Quarantine on "+h.Name+"?", fmt.Sprintf("%v", sub[1:])); err != nil {
					return err
				}
			}
			return o.Run(cmd.Context(), h, sub, os.Stdout, os.Stderr, nil)
		},
	}
	c.Flags().SetInterspersed(false)
	sshFlags(c, &o)
	c.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask before quarantine")
	return c
}
