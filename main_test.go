package main

import (
	"slices"
	"testing"
)

func TestSingleDashLongFlags(t *testing.T) {
	root := rootCmd()
	in := []string{"sweep", "-watch", "30m", "-pkg=false", "-j", "4", "-i", "key", "-o", "Port=22", "host", "--", "-max"}
	want := []string{"sweep", "--watch", "30m", "--pkg=false", "-j", "4", "-i", "key", "-o", "Port=22", "host", "--", "-max"}
	if got := singleDashLongFlags(root, in); !slices.Equal(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	remote := []string{"remote", "root@h", "quarantine", "-kill", "/usr/sbin/x"}
	if got := singleDashLongFlags(root, remote); got[3] != "--kill" {
		t.Fatalf("target flags should be rewritten too: %q", got)
	}
}
