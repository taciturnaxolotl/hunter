// Package target is the half of hunter that runs on a box: it collects
// observations straight from /proc, /etc and the package databases, and
// inspects or quarantines files, without trusting the box's own tools.
package target

import (
	"errors"
	"time"
)

type Options struct {
	Since      time.Duration // timestomp window
	PkgVerify  bool
	PkgTimeout time.Duration
	Rules      []string // extra indicator packs as raw JSON
	SkipDirs   []string // hunter's own state, never walked
	Version    string
}

// ErrTargetOnly is returned on platforms that cannot be a target.
var ErrTargetOnly = errors.New("this subcommand runs on a Linux target; use `hunter sweep` or `hunter remote` from here")
