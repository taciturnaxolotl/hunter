package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/taciturnaxolotl/hunter/internal/remote"
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
	)
	c := &cobra.Command{
		Use:    "quarantine PATH...",
		Short:  "Move files to ~/.quarantine with a manifest",
		Args:   cobra.MinimumNArgs(1),
		PreRun: verifyTransfer,
		RunE: func(cmd *cobra.Command, args []string) error {
			return target.Quarantine(os.Stdout, args, dir, kill)
		},
	}
	c.Flags().BoolVar(&kill, "kill", false, "SIGKILL processes running the file first")
	c.Flags().StringVar(&dir, "dir", "", "quarantine directory (default ~/.quarantine)")
	return c
}
