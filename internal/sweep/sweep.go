// Package sweep runs collect on many hosts in parallel, files each
// snapshot in the store, and diffs it against that host's baseline.
package sweep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/taciturnaxolotl/hunter/internal/remote"
	"github.com/taciturnaxolotl/hunter/internal/sanitize"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
)

type Options struct {
	SSH        remote.Options
	Store      snapshot.Store
	Jobs       int
	Rebase     bool          // make this sweep every host's baseline
	Since      time.Duration // timestomp window; 0 = since baseline, else 24h
	PkgVerify  bool
	PkgTimeout time.Duration
	Rules      []string // extra indicator packs as raw JSON, shipped inline
}

type Phase int

const (
	Queued Phase = iota
	Connecting
	Collecting
	Done
)

func (p Phase) String() string {
	return [...]string{"queued", "connecting", "collecting", "done"}[p]
}

// Event reports progress on one host. Result is set once Phase is Done.
type Event struct {
	Host   remote.Host
	Phase  Phase
	Result *Result
}

type Result struct {
	Host     remote.Host
	Snap     *snapshot.Snapshot
	Changes  []snapshot.Change
	NewBase  bool
	BaseTime time.Time
	Err      error
}

// Round sweeps every host once. notify, when non-nil, is called for each
// progress event, never concurrently. Results come back sorted by name.
func Round(ctx context.Context, o *Options, hosts []remote.Host, notify func(Event)) []Result {
	var mu sync.Mutex
	emit := func(e Event) {
		if notify == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		notify(e)
	}
	for _, h := range hosts {
		emit(Event{Host: h, Phase: Queued})
	}

	results := make([]Result, len(hosts))
	sem := make(chan struct{}, max(o.Jobs, 1))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = Result{Host: h, Err: ctx.Err()}
				emit(Event{Host: h, Phase: Done, Result: &results[i]})
				return
			}
			defer func() { <-sem }()
			results[i] = one(ctx, o, h, func(p Phase) { emit(Event{Host: h, Phase: p}) })
			emit(Event{Host: h, Phase: Done, Result: &results[i]})
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Host.Name < results[j].Host.Name })
	return results
}

func one(ctx context.Context, o *Options, h remote.Host, phase func(Phase)) Result {
	r := Result{Host: h}
	base, _ := o.Store.Baseline(h.Name)

	since := o.Since
	if since == 0 {
		since = 24 * time.Hour
		if base != nil && !o.Rebase {
			since = time.Since(base.Time) + 15*time.Minute
		}
	}
	args := []string{"collect", "--since", since.Round(time.Second).String(), "--pkg-timeout", o.PkgTimeout.String()}
	if !o.PkgVerify {
		args = append(args, "--pkg=false")
	}
	for _, raw := range o.Rules {
		args = append(args, "--rules-json", raw)
	}

	var stdout, stderr bytes.Buffer
	err := o.SSH.Run(ctx, h, args, &stdout, &stderr, func(p remote.Phase) {
		if p == remote.Connecting {
			phase(Connecting)
		} else {
			phase(Collecting)
		}
	})
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		r.Err = errors.New(msg)
		return r
	}
	var snap snapshot.Snapshot
	if err := json.Unmarshal(stdout.Bytes(), &snap); err != nil {
		r.Err = fmt.Errorf("bad collector output: %v %s", err, sanitize.Clean(stderr.String(), 200))
		return r
	}
	return Record(o.Store, h, &snap, base, o.Rebase)
}

// Record files a fresh snapshot of h and diffs it against base, which
// becomes snap itself when there is none yet or rebase is set.
func Record(st snapshot.Store, h remote.Host, snap, base *snapshot.Snapshot, rebase bool) Result {
	r := Result{Host: h, Snap: snap, NewBase: base == nil || rebase}
	if err := st.Save(h.Name, snap, r.NewBase); err != nil {
		r.Err = err
		return r
	}
	if !r.NewBase {
		r.BaseTime = base.Time
		r.Changes = snapshot.Diff(base, snap)
	}
	return r
}
