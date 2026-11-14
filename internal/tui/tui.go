// Package tui is the live sweep view: one row per host filling in as the
// sweep runs, and in watch mode a browsable dashboard between rounds.
package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"

	"github.com/taciturnaxolotl/hunter/internal/remote"
	"github.com/taciturnaxolotl/hunter/internal/report"
	"github.com/taciturnaxolotl/hunter/internal/sanitize"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"github.com/taciturnaxolotl/hunter/internal/sweep"
)

type view int

const (
	listView view = iota
	detailView
	confirmView
)

type row struct {
	phase  sweep.Phase
	result *sweep.Result
}

// Model drives one or more sweep rounds. Without Watch it quits as soon
// as the first round finishes.
type Model struct {
	opts  *sweep.Options
	hosts []remote.Host
	watch time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	rows    map[string]*row
	stream  roundStream
	round   int
	running bool
	started time.Time
	next    time.Time
	last    []sweep.Result
	took    time.Duration

	view     view
	cursor   int
	quitting bool
	flash    string
	width    int
	height   int

	spin spinner.Model
	vp   viewport.Model
	help help.Model
	keys keyMap
}

func New(ctx context.Context, opts *sweep.Options, hosts []remote.Host, watch time.Duration) *Model {
	ctx, cancel := context.WithCancel(ctx)
	m := &Model{
		opts: opts, hosts: hosts, watch: watch,
		ctx: ctx, cancel: cancel,
		rows: map[string]*row{},
		spin: spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(report.Yellow)),
		vp:   viewport.New(),
		help: help.New(),
		keys: defaultKeys(),
	}
	for _, h := range hosts {
		m.rows[h.Name] = &row{}
	}
	return m
}

// Results is the most recent complete round, for printing after exit.
func (m *Model) Results() ([]sweep.Result, time.Duration) { return m.last, m.took }

type (
	eventMsg     sweep.Event
	roundDoneMsg struct {
		results []sweep.Result
		took    time.Duration
	}
	tickMsg     time.Time
	roundStream chan tea.Msg
)

func waitFor(ch roundStream) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

func (m *Model) startRound() tea.Cmd {
	m.round++
	m.running = true
	m.started = time.Now()
	if m.round > 1 {
		m.opts.Rebase = false
	}
	ch := make(roundStream, 64)
	opts := *m.opts
	go func() {
		start := time.Now()
		res := sweep.Round(m.ctx, &opts, m.hosts, func(e sweep.Event) { ch <- eventMsg(e) })
		ch <- roundDoneMsg{results: res, took: time.Since(start)}
	}()
	m.stream = ch
	return tea.Batch(waitFor(ch), m.spin.Tick)
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) Init() tea.Cmd { return m.startRound() }

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.help.SetWidth(msg.Width)
		m.vp.SetWidth(msg.Width)
		m.vp.SetHeight(max(msg.Height-3, 1))
		return m, nil

	case eventMsg:
		r := m.rows[msg.Host.Name]
		r.phase = msg.Phase
		if msg.Result != nil {
			res := *msg.Result
			r.result = &res
		}
		return m, waitFor(m.stream)

	case roundDoneMsg:
		m.running = false
		m.last, m.took = msg.results, msg.took
		if m.watch <= 0 || m.ctx.Err() != nil {
			m.quitting = true
			return m, tea.Quit
		}
		m.next = time.Now().Add(m.watch)
		return m, tick()

	case tickMsg:
		if m.running {
			return m, nil
		}
		if !time.Time(msg).Before(m.next) {
			return m, m.startRound()
		}
		return m, tick()

	case spinner.TickMsg:
		if !m.running {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) quit() (tea.Model, tea.Cmd) {
	m.cancel()
	if m.running {
		m.flash = "stopping, waiting for ssh sessions to end"
		return m, nil
	}
	m.quitting = true
	return m, tea.Quit
}

func (m *Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if key.Matches(msg, m.keys.ForceQuit) {
		return m.quit()
	}
	switch m.view {
	case detailView:
		if key.Matches(msg, m.keys.Back, m.keys.Quit) {
			m.view = listView
			return m, nil
		}
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd

	case confirmView:
		h := m.hosts[m.cursor]
		switch msg.String() {
		case "y", "Y":
			if s, err := m.opts.Store.Promote(h.Name); err != nil {
				m.flash = report.Red.Render(err.Error())
			} else {
				m.flash = fmt.Sprintf("baseline for %s is now the %s sweep", h.Name, s.Time.Local().Format("15:04:05"))
			}
		default:
			m.flash = "baseline unchanged"
		}
		m.view = listView
		return m, nil
	}

	m.flash = ""
	switch {
	case key.Matches(msg, m.keys.Quit):
		return m.quit()
	case key.Matches(msg, m.keys.Up):
		m.cursor = max(m.cursor-1, 0)
	case key.Matches(msg, m.keys.Down):
		m.cursor = min(m.cursor+1, len(m.hosts)-1)
	case key.Matches(msg, m.keys.Open):
		if r := m.rows[m.hosts[m.cursor].Name].result; r != nil {
			m.vp.SetContent(detail(*r))
			m.vp.GotoTop()
			m.view = detailView
		}
	case key.Matches(msg, m.keys.Baseline):
		if r := m.rows[m.hosts[m.cursor].Name].result; r != nil && r.Snap != nil {
			m.view = confirmView
		} else {
			m.flash = "no successful sweep of this host yet"
		}
	case key.Matches(msg, m.keys.SweepNow):
		if !m.running && m.watch > 0 {
			return m, m.startRound()
		}
	}
	return m, nil
}

func detail(r sweep.Result) string {
	s := report.RenderResult(r, 0)
	if r.Snap != nil && !r.NewBase {
		if crit := r.Snap.Filter(snapshot.Crit, ""); len(crit) > 0 {
			s += "\n" + report.Bold.Render("  all crit findings") + "\n" + report.RenderFindings(crit, 0) + "\n"
		}
	}
	return s
}

func (m *Model) View() tea.View {
	var v tea.View
	if m.watch > 0 {
		v.AltScreen = true
	}
	if m.quitting {
		// the full report is printed after exit; leave no stale table behind
		return v
	}
	if m.view == detailView {
		h := m.hosts[m.cursor].Name
		footer := report.Dim.Render(fmt.Sprintf(" %s  %3.0f%%  ", h, m.vp.ScrollPercent()*100)) + m.help.View(detailKeys{m.keys})
		v.SetContent(m.vp.View() + "\n" + footer)
		return v
	}

	var b strings.Builder
	b.WriteString(m.header() + "\n")
	b.WriteString(m.table() + "\n")
	switch {
	case m.view == confirmView:
		b.WriteString(report.Yellow.Render(fmt.Sprintf("  make the latest sweep of %s its baseline? [y/N]", m.hosts[m.cursor].Name)) + "\n")
	case m.flash != "":
		b.WriteString("  " + m.flash + "\n")
	}
	if m.watch > 0 {
		b.WriteString("  " + m.help.View(m.keys) + "\n")
	}
	v.SetContent(b.String())
	return v
}

func (m *Model) header() string {
	title := report.Bold.Render("hunter") + fmt.Sprintf(" sweep %d of %d hosts", m.round, len(m.hosts))
	var status string
	switch {
	case m.running:
		done := 0
		for _, r := range m.rows {
			if r.phase == sweep.Done {
				done++
			}
		}
		status = fmt.Sprintf("%s %d/%d  %s", m.spin.View(), done, len(m.hosts), time.Since(m.started).Round(time.Second))
	case m.watch > 0:
		status = fmt.Sprintf("took %s, next in %s", m.took.Round(time.Second), time.Until(m.next).Round(time.Second))
	}
	return title + "  " + report.Dim.Render(status)
}

func (m *Model) table() string {
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(report.Dim).
		Headers("", "host", "state", "crit", "warn", "changes")
	for _, h := range m.hosts {
		r := m.rows[h.Name]
		t.Row(m.icon(r), h.Name, state(r), count(r, snapshot.Crit), count(r, snapshot.Warn), changes(r))
	}
	selected := lipgloss.NewStyle().Reverse(true)
	t.StyleFunc(func(rowIdx, col int) lipgloss.Style {
		base := lipgloss.NewStyle().Padding(0, 1)
		if rowIdx == table.HeaderRow {
			return base.Inherit(report.Dim)
		}
		if col >= 3 {
			base = base.Align(lipgloss.Right)
		}
		r := m.rows[m.hosts[rowIdx].Name]
		switch {
		case col == 3 && r.result != nil && r.result.Snap != nil:
			crit, _, _ := r.result.Snap.Counts()
			base = base.Inherit(report.SevStyle(snapshot.Crit, crit))
		case col == 4 && r.result != nil && r.result.Snap != nil:
			_, warn, _ := r.result.Snap.Counts()
			base = base.Inherit(report.SevStyle(snapshot.Warn, warn))
		case col == 2 && r.result != nil && r.result.Err != nil:
			base = base.Inherit(report.Red)
		}
		if m.watch > 0 && rowIdx == m.cursor && col == 1 {
			base = base.Inherit(selected)
		}
		return base
	})
	if m.width > 0 && lipgloss.Width(t.String()) > m.width-2 {
		t.Width(m.width - 2)
	}
	return lipgloss.NewStyle().PaddingLeft(2).Render(t.String())
}

func (m *Model) icon(r *row) string {
	switch {
	case m.running && (r.phase == sweep.Connecting || r.phase == sweep.Collecting):
		return m.spin.View()
	case r.result == nil:
		return report.Dim.Render("·")
	case r.result.Err != nil:
		return report.Red.Render("✗")
	}
	return report.Green.Render("✓")
}

func state(r *row) string {
	if r.phase != sweep.Done || r.result == nil {
		return r.phase.String()
	}
	if r.result.Err != nil {
		return sanitize.Clean(r.result.Err.Error(), 30)
	}
	return "done"
}

func count(r *row, sev snapshot.Sev) string {
	if r.result == nil || r.result.Snap == nil {
		return ""
	}
	crit, warn, _ := r.result.Snap.Counts()
	if sev == snapshot.Crit {
		return strconv.Itoa(crit)
	}
	return strconv.Itoa(warn)
}

func changes(r *row) string {
	switch {
	case r.result == nil || r.result.Snap == nil:
		return ""
	case r.result.NewBase:
		return "new baseline"
	}
	return strconv.Itoa(len(r.result.Changes))
}
