package tui

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/taciturnaxolotl/hunter/internal/remote"
	"github.com/taciturnaxolotl/hunter/internal/report"
	"github.com/taciturnaxolotl/hunter/internal/sanitize"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"github.com/taciturnaxolotl/hunter/internal/sweep"
)

// ScanConfig is everything the single-box view needs.
type ScanConfig struct {
	Host    remote.Host
	Store   snapshot.Store
	Collect func() (*snapshot.Snapshot, error)
	Rebase  bool          // make the first scan the baseline
	Watch   time.Duration // rescan interval; 0 = only on demand
	Sev     snapshot.Sev  // starting severity for the findings tab
	Fix     func() *exec.Cmd
}

type tab int

const (
	changesTab tab = iota
	findingsTab
)

// Scan is the pager for hunting on the box you are logged into: what
// changed since the baseline, every finding by severity, rescans on a
// timer, and a hand-off to the fix walkthrough.
type Scan struct {
	cfg ScanConfig

	result   *sweep.Result
	scanning bool
	started  time.Time
	next     time.Time
	rounds   int

	tab      tab
	sev      snapshot.Sev
	confirm  bool
	flash    string
	quitting bool
	width    int
	height   int

	spin spinner.Model
	vp   viewport.Model
	help help.Model
	keys scanKeys
}

func NewScan(cfg ScanConfig) *Scan {
	return &Scan{
		cfg:  cfg,
		sev:  cfg.Sev,
		spin: spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(report.Yellow)),
		vp:   viewport.New(),
		help: help.New(),
		keys: defaultScanKeys(cfg.Fix != nil),
	}
}

// Result is the last finished scan, for printing after exit.
func (m *Scan) Result() *sweep.Result { return m.result }

type (
	scanDoneMsg struct{ r sweep.Result }
	fixDoneMsg  struct{ err error }
)

func (m *Scan) startScan() tea.Cmd {
	m.scanning = true
	m.started = time.Now()
	rebase := m.cfg.Rebase && m.rounds == 0
	m.rounds++
	cfg := m.cfg
	scan := func() tea.Msg {
		base, _ := cfg.Store.Baseline(cfg.Host.Name)
		snap, err := cfg.Collect()
		if err != nil {
			return scanDoneMsg{sweep.Result{Host: cfg.Host, Err: err}}
		}
		return scanDoneMsg{sweep.Record(cfg.Store, cfg.Host, snap, base, rebase)}
	}
	return tea.Batch(scan, m.spin.Tick)
}

func (m *Scan) Init() tea.Cmd { return m.startScan() }

func (m *Scan) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.help.SetWidth(msg.Width)
		m.vp.SetWidth(msg.Width)
		m.vp.SetHeight(max(msg.Height-4, 1))
		m.refresh(false)
		return m, nil

	case scanDoneMsg:
		m.scanning = false
		if msg.r.Err != nil {
			m.flash = report.Red.Render("scan failed: " + sanitize.Clean(msg.r.Err.Error(), 200))
			if m.result == nil {
				m.result = &msg.r
			}
		} else {
			first := m.result == nil || m.result.Snap == nil
			m.result = &msg.r
			if first && msg.r.NewBase {
				m.tab = findingsTab
			}
			m.refresh(first)
		}
		if m.cfg.Watch > 0 {
			m.next = time.Now().Add(m.cfg.Watch)
			return m, tick()
		}
		return m, nil

	case tickMsg:
		if m.scanning || m.cfg.Watch <= 0 {
			return m, nil
		}
		if !time.Time(msg).Before(m.next) {
			return m, m.startScan()
		}
		return m, tick()

	case fixDoneMsg:
		if msg.err != nil {
			m.flash = report.Red.Render("walkthrough: " + msg.err.Error())
		}
		return m, m.startScan()

	case spinner.TickMsg:
		if !m.scanning {
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

func (m *Scan) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.confirm {
		m.confirm = false
		if msg.String() == "y" || msg.String() == "Y" {
			if s, err := m.cfg.Store.Promote(m.cfg.Host.Name); err != nil {
				m.flash = report.Red.Render(err.Error())
			} else {
				m.flash = "baseline is now the " + s.Time.Local().Format("15:04:05") + " scan"
				if m.result != nil {
					m.result.NewBase, m.result.Changes = true, nil
					m.refresh(true)
				}
			}
		} else {
			m.flash = "baseline unchanged"
		}
		return m, nil
	}
	m.flash = ""
	switch {
	case key.Matches(msg, m.keys.Quit):
		m.quitting = true
		return m, tea.Quit
	case key.Matches(msg, m.keys.Tab):
		m.tab = 1 - m.tab
		m.refresh(true)
	case key.Matches(msg, m.keys.Sev):
		m.sev = (m.sev + 2) % 3 // crit -> warn -> info -> crit
		m.tab = findingsTab
		m.refresh(true)
	case key.Matches(msg, m.keys.Rescan):
		if !m.scanning {
			return m, m.startScan()
		}
	case key.Matches(msg, m.keys.Baseline):
		if m.result != nil && m.result.Snap != nil {
			m.confirm = true
		}
	case key.Matches(msg, m.keys.Fix):
		if m.cfg.Fix != nil && !m.scanning {
			return m, tea.ExecProcess(m.cfg.Fix(), func(err error) tea.Msg { return fixDoneMsg{err} })
		}
	default:
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	}
	return m, nil
}

// refresh rebuilds the pager content, keeping the scroll position unless
// what is shown changed.
func (m *Scan) refresh(top bool) {
	r := m.result
	var s string
	switch {
	case r == nil || r.Snap == nil:
		s = ""
	case m.tab == changesTab && r.NewBase:
		s = "\n" + report.Dim.Render("  this scan is the baseline; later scans show what changed against it") + "\n"
	case m.tab == changesTab:
		s = "\n" + report.Dim.Render(fmt.Sprintf("  since the baseline from %s:", r.BaseTime.Local().Format("Jan 2 15:04"))) +
			"\n" + report.RenderChanges(r.Changes, 0) + "\n"
	default:
		s = "\n" + report.RenderFindings(r.Snap.Filter(m.sev, ""), 0) + "\n"
	}
	for _, e := range errorsOf(r) {
		s += "\n" + report.Dim.Render("  collector error: "+sanitize.Clean(e, 200))
	}
	m.vp.SetContent(s)
	if top {
		m.vp.GotoTop()
	}
}

func errorsOf(r *sweep.Result) []string {
	if r == nil || r.Snap == nil {
		return nil
	}
	return r.Snap.Errors
}

func (m *Scan) View() tea.View {
	v := tea.View{AltScreen: true}
	if m.quitting {
		return v
	}
	var b strings.Builder
	b.WriteString(m.header() + "\n")
	b.WriteString(m.tabs() + "\n")
	b.WriteString(m.vp.View() + "\n")
	switch {
	case m.confirm:
		b.WriteString(report.Yellow.Render(" make this scan the baseline? [y/N]"))
	case m.flash != "":
		b.WriteString(" " + m.flash)
	default:
		b.WriteString(" " + m.help.View(m.keys))
	}
	v.SetContent(b.String())
	return v
}

func (m *Scan) header() string {
	h := report.Bold.Render("hunter") + " " + m.cfg.Host.Name
	if r := m.result; r != nil && r.Snap != nil {
		crit, warn, _ := r.Snap.Counts()
		h += "  " + report.SevStyle(snapshot.Crit, crit).Render(fmt.Sprintf("%d crit", crit)) + ", " +
			report.SevStyle(snapshot.Warn, warn).Render(fmt.Sprintf("%d warn", warn))
		if !r.NewBase {
			h += fmt.Sprintf(", %d changed", len(r.Changes))
		}
	}
	var status string
	switch {
	case m.scanning:
		status = m.spin.View() + " scanning " + time.Since(m.started).Round(time.Second).String()
	case m.result != nil && m.result.Snap != nil:
		status = "scanned " + m.result.Snap.Time.Local().Format("15:04:05")
		if m.cfg.Watch > 0 {
			status += ", next in " + time.Until(m.next).Round(time.Second).String()
		}
	}
	return h + "  " + report.Dim.Render(status)
}

func (m *Scan) tabs() string {
	active := lipgloss.NewStyle().Bold(true).Underline(true)
	names := []string{"changes", "findings ≥ " + m.sev.String()}
	var parts []string
	for i, n := range names {
		if tab(i) == m.tab {
			parts = append(parts, active.Render(n))
		} else {
			parts = append(parts, report.Dim.Render(n))
		}
	}
	return " " + strings.Join(parts, "   ")
}

type scanKeys struct {
	Tab, Sev, Rescan, Baseline, Fix, Scroll, Quit key.Binding
}

func defaultScanKeys(fix bool) scanKeys {
	k := scanKeys{
		Tab:      key.NewBinding(key.WithKeys("tab", "left", "right"), key.WithHelp("tab", "changes/findings")),
		Sev:      key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "severity")),
		Rescan:   key.NewBinding(key.WithKeys("s", "r"), key.WithHelp("s", "scan now")),
		Baseline: key.NewBinding(key.WithKeys("b"), key.WithHelp("b", "accept as baseline")),
		Fix:      key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "fix walkthrough")),
		Scroll:   key.NewBinding(key.WithKeys("up", "down"), key.WithHelp("↑/↓/pgup/pgdn", "scroll")),
		Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
	k.Fix.SetEnabled(fix)
	return k
}

func (k scanKeys) ShortHelp() []key.Binding {
	return []key.Binding{k.Scroll, k.Tab, k.Sev, k.Rescan, k.Fix, k.Baseline, k.Quit}
}

func (k scanKeys) FullHelp() [][]key.Binding { return [][]key.Binding{k.ShortHelp()} }
