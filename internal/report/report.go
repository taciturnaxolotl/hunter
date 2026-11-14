// Package report turns snapshots, diffs and sweep results into output:
// a styled report for people, or sanitized JSON lines for a model.
package report

import (
	"time"

	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"github.com/taciturnaxolotl/hunter/internal/sweep"
)

// Reporter is one output mode. Every command that prints findings goes
// through it, so a new mode never touches the commands.
type Reporter interface {
	SweepStart(round, hosts int, at time.Time)
	SweepHost(r sweep.Result)
	SweepEnd(results []sweep.Result, took time.Duration)
	// Findings prints observations already filtered and sorted.
	Findings(host string, s *snapshot.Snapshot, obs []snapshot.Obs)
	Diff(host string, old, cur *snapshot.Snapshot, changes []snapshot.Change)
}
