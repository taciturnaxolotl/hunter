//go:build !linux

package target

import (
	"io"

	"github.com/taciturnaxolotl/hunter/internal/snapshot"
)

func Collect(Options) (*snapshot.Snapshot, error)        { return nil, ErrTargetOnly }
func Inspect(io.Writer, []string, int) error             { return ErrTargetOnly }
func Quarantine(io.Writer, []string, string, bool) error { return ErrTargetOnly }
func Ownership() func(string) bool                       { return nil }
func Running(string) []int                               { return nil }
func Kill(Proc) error                                    { return ErrTargetOnly }
