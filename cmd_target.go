package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/taciturnaxolotl/hunter/internal/remote"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"github.com/taciturnaxolotl/hunter/internal/target"
)

// verifyTransfer refuses to run a target command when the binary is not
// the one the laptop sent.
func verifyTransfer(*cobra.Command, []string) {
	if err := remote.VerifySelf(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
}

func collectCmd() *cobra.Command {
	var (
		o         = target.Options{Version: version}
		ruleFiles []string
		pretty    bool
	)
	c := &cobra.Command{
		Use:    "collect",
		Short:  "Print a JSON snapshot of this box",
		Args:   cobra.NoArgs,
		PreRun: verifyTransfer,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, f := range ruleFiles {
				b, err := os.ReadFile(f)
				if err != nil {
					return err
				}
				o.Rules = append(o.Rules, string(b))
			}
			o.SkipDirs = ownDirs()
			o.Rules = append(o.Rules, localRules()...)
			snap, err := target.Collect(o)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			if pretty {
				enc.SetIndent("", " ")
			}
			return enc.Encode(snap)
		},
	}
	f := c.Flags()
	f.DurationVar(&o.Since, "since", 24*time.Hour, "timestomp window: files whose inode changed within this window but claim an older mtime")
	f.BoolVar(&o.PkgVerify, "pkg", true, "verify installed packages (rpm -Va / dpkg --verify / pacman -Qkk)")
	f.DurationVar(&o.PkgTimeout, "pkg-timeout", 4*time.Minute, "package verify timeout")
	f.StringArrayVar(&ruleFiles, "rules", nil, "extra indicator pack file (repeatable)")
	f.StringArrayVar(&o.Rules, "rules-json", nil, "extra indicator pack as inline JSON (repeatable)")
	f.BoolVar(&pretty, "pretty", false, "indent JSON")
	return c
}

func inspectCmd() *cobra.Command {
	var n int
	c := &cobra.Command{
		Use:    "inspect PATH...",
		Short:  "Stat, hash, caps, ELF info and strings of files",
		Args:   cobra.MinimumNArgs(1),
		PreRun: verifyTransfer,
		RunE: func(cmd *cobra.Command, args []string) error {
			return target.Inspect(os.Stdout, args, n)
		},
	}
	c.Flags().IntVar(&n, "strings", 80, "interesting strings to print")
	return c
}

func quarantineCmd() *cobra.Command {
	var (
		kill bool
		dir  string
		runs string
		sevS string
	)
	c := &cobra.Command{
		Use:   "quarantine [PATH...]",
		Short: "Move files to ~/.quarantine, or step through fixes with no paths",
		Long: "With paths, move each to the quarantine directory (chmod 0, metadata in\n" +
			"MANIFEST.jsonl). With none, walk through every finding from the latest scan of\n" +
			"this box, one at a time: inspect, kill, quarantine, edit, or mark it known-good\n" +
			"(saved to the box's allow list). Nothing happens unless chosen, and packaged or\n" +
			"system files are never offered for quarantine.",
		Example: "  sudo ./hunter quarantine\n  hunter quarantine --kill /usr/sbin/rt-tagd",
		PreRun:  verifyTransfer,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				dir = quarantineDir()
			}
			if len(args) == 0 {
				sev, err := snapshot.ParseSev(sevS)
				if err != nil {
					return err
				}
				return fixWalkthrough(runs, sev, dir)
			}
			return target.Quarantine(os.Stdout, args, dir, kill)
		},
	}
	f := c.Flags()
	f.BoolVar(&kill, "kill", false, "SIGKILL processes running the file first")
	f.StringVar(&dir, "dir", "", "quarantine directory (default ~/.quarantine)")
	f.StringVar(&runs, "runs", localRuns(), "walkthrough: where hunter scan keeps its scans")
	f.StringVar(&sevS, "sev", "warn", "walkthrough: lowest severity to step through")
	return c
}
