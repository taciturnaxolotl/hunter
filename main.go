// hunter: agentless threat hunting for NCAE/CCDC style blue team boxes.
//
// The same static binary is both halves. On your laptop it pushes itself
// over SSH to every box and diffs results against a baseline. On a box it
// collects observations straight from /proc, /etc and the package
// databases, without trusting the box's own ps/ss/ls/lsattr.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"charm.land/fang/v2"
	"charm.land/log/v2"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var version = "0.1.0"

var logger = log.NewWithOptions(os.Stderr, log.Options{
	ReportTimestamp: true,
	TimeFormat:      time.Kitchen,
	Prefix:          "hunter",
})

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "hunter",
		Short: "Agentless threat hunting over SSH",
		Long: "Agentless threat hunting for competition boxes. On your laptop hunter pushes itself\n" +
			"to every box over SSH, collects, and diffs against a baseline. On a box it reads\n" +
			"/proc, /etc and the package databases directly instead of trusting the box's own tools.\n\n" +
			"Logged into a Linux box, plain `hunter` is `hunter scan`.",
		Args: cobra.NoArgs,
	}
	if runtime.GOOS == "linux" {
		scan := scanCmd()
		root.Flags().AddFlagSet(scan.Flags())
		root.RunE = scan.RunE
	}
	root.AddGroup(
		&cobra.Group{ID: "laptop", Title: "Laptop"},
		&cobra.Group{ID: "target", Title: "On a box (logged in, or through remote)"},
	)
	for _, c := range []*cobra.Command{sweepCmd(), showCmd(), diffCmd(), baselineCmd(), remoteCmd()} {
		c.GroupID = "laptop"
		root.AddCommand(c)
	}
	for _, c := range []*cobra.Command{scanCmd(), collectCmd(), inspectCmd(), quarantineCmd()} {
		c.GroupID = "target"
		root.AddCommand(c)
	}
	return root
}

func main() {
	root := rootCmd()
	root.SetArgs(singleDashLongFlags(root, os.Args[1:]))
	err := fang.Execute(context.Background(), root,
		fang.WithVersion(version),
		fang.WithNotifySignal(os.Interrupt),
		fang.WithErrorHandler(errorHandler),
	)
	if err != nil {
		os.Exit(1)
	}
}

// errorHandler keeps fang's styled errors for people, and prints a single
// plain line when stderr is not a terminal: on a box it is read back by
// the laptop and shown as the host's failure.
func errorHandler(w io.Writer, styles fang.Styles, err error) {
	if !isTerminal(os.Stderr) {
		fmt.Fprintln(w, "hunter:", err)
		return
	}
	fang.DefaultErrorHandler(w, styles, err)
}

// singleDashLongFlags rewrites -sev to --sev for every long flag hunter
// defines, so Go-style flags in scripts, muscle memory and the hunt skill
// keep working under pflag. Single letters stay shorthands (-j, -i, -o).
func singleDashLongFlags(root *cobra.Command, args []string) []string {
	known := map[string]bool{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) { known[f.Name] = true })
		c.PersistentFlags().VisitAll(func(f *pflag.Flag) { known[f.Name] = true })
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	out := make([]string, len(args))
	for i, a := range args {
		if a == "--" {
			copy(out[i:], args[i:])
			break
		}
		if len(a) > 2 && a[0] == '-' && a[1] != '-' {
			if name, _, _ := strings.Cut(a[1:], "="); len(name) > 1 && known[name] {
				a = "-" + a
			}
		}
		out[i] = a
	}
	return out
}

func isTerminal(f *os.File) bool { return term.IsTerminal(f.Fd()) }
