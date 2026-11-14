package report

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"charm.land/lipgloss/v2/tree"

	"github.com/taciturnaxolotl/hunter/internal/sanitize"
	"github.com/taciturnaxolotl/hunter/internal/snapshot"
	"github.com/taciturnaxolotl/hunter/internal/sweep"
)

// Human is the styled report. Colors are downsampled or dropped to suit
// W (a pipe, NO_COLOR, a dumb terminal) when written.
type Human struct {
	W   io.Writer
	Max int // findings or changes shown per host; 0 = all
}

func (h Human) print(s string) { lipgloss.Fprint(h.W, s) }

func (h Human) SweepStart(round, hosts int, at time.Time) {
	h.print(fmt.Sprintf("%s sweep %d of %d hosts at %s\n\n", Bold.Render("hunter"), round, hosts, at.Format("15:04:05")))
}

func (h Human) SweepHost(r sweep.Result) { h.print(RenderResult(r, h.Max) + "\n") }

func (h Human) SweepEnd(results []sweep.Result, took time.Duration) {
	h.print(Green.Render("[+]") + " summary " + Dim.Render("("+took.Round(time.Second).String()+")") + "\n")
	h.print(Summary(results) + "\n")
}

func (h Human) Findings(host string, s *snapshot.Snapshot, obs []snapshot.Obs) {
	h.print(HostHeader(host, s) + "\n" + RenderFindings(obs, h.Max) + "\n\n")
}

func (h Human) Diff(host string, old, cur *snapshot.Snapshot, changes []snapshot.Change) {
	h.print(fmt.Sprintf("%s %s  %s\n", Green.Render("[+]"), Bold.Render(host),
		Dim.Render(old.Time.Format(time.RFC3339)+" -> "+cur.Time.Format(time.RFC3339))))
	h.print(RenderChanges(changes, h.Max) + "\n")
}

// indent shifts every line right. A lipgloss padding style would also pad
// each line out to the widest one, leaving trailing spaces everywhere.
func indent(s string) string { return "  " + strings.ReplaceAll(s, "\n", "\n  ") }

// HostHeader is the one-line summary of a host's latest snapshot, plus any
// errors the collector hit.
func HostHeader(name string, s *snapshot.Snapshot) string {
	crit, warn, _ := s.Counts()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s  %s, %s  %s", Green.Render("[+]"), Bold.Render(name),
		SevStyle(snapshot.Crit, crit).Render(fmt.Sprintf("%d crit", crit)),
		SevStyle(snapshot.Warn, warn).Render(fmt.Sprintf("%d warn", warn)),
		Dim.Render(fmt.Sprintf("%s %s pkg=%s %s", sanitize.Clean(s.Hostname, 60), sanitize.Clean(s.OS, 40), s.PkgMgr, s.Elapsed)))
	for _, e := range s.Errors {
		b.WriteString("\n" + indent(Dim.Render("collector error: "+sanitize.Clean(e, 200))))
	}
	return b.String()
}

// RenderResult is everything one host's sweep has to say.
func RenderResult(r sweep.Result, max int) string {
	if r.Err != nil {
		return fmt.Sprintf("%s %s  %s\n", Red.Render("[!]"), Bold.Render(r.Host.Name), Red.Render(sanitize.Clean(r.Err.Error(), 300)))
	}
	var b strings.Builder
	b.WriteString(HostHeader(r.Host.Name, r.Snap) + "\n")
	if r.NewBase {
		b.WriteString(indent(Dim.Render("baseline saved; findings at warn and above:")) + "\n")
		b.WriteString(RenderFindings(r.Snap.Filter(snapshot.Warn, ""), max) + "\n")
		return b.String()
	}
	ago := time.Since(r.BaseTime).Round(time.Minute)
	b.WriteString(indent(Dim.Render("changes since baseline ("+ago.String()+" ago):")) + "\n")
	b.WriteString(RenderChanges(r.Changes, max) + "\n")
	if crit, _, _ := r.Snap.Counts(); crit > 0 {
		b.WriteString(indent(Red.Render(fmt.Sprintf("%d crit findings present in total", crit))+
			Dim.Render("  (hunter show --sev crit "+r.Host.Name+")")) + "\n")
	}
	return b.String()
}

func obsBody(o snapshot.Obs) string {
	line := SevTag(o.Sev) + " " + sanitize.Clean(o.Msg, 160)
	sub := Dim.Render(sanitize.Clean(o.Key, 160))
	if o.Detail != "" {
		d := sanitize.Clean(o.Detail, 220)
		if o.Sev == snapshot.Crit {
			d = Red.UnsetBold().Render(d)
		}
		sub += "  " + d
	}
	return line + "\n     " + sub
}

// RenderFindings groups observations by check, loudest check first, each
// finding showing its message and then its key and detail.
func RenderFindings(obs []snapshot.Obs, max int) string {
	if len(obs) == 0 {
		return indent(Green.Render("nothing to report"))
	}
	shown := obs
	if max > 0 && len(shown) > max {
		shown = shown[:max]
	}
	groups := map[string]*tree.Tree{}
	var order []string
	counts := map[string]int{}
	for _, o := range obs {
		counts[o.Check]++
	}
	for _, o := range shown {
		g, ok := groups[o.Check]
		if !ok {
			g = tree.Root(Bold.Render(o.Check) + Dim.Render(" "+strconv.Itoa(counts[o.Check])))
			groups[o.Check] = g
			order = append(order, o.Check)
		}
		g.Child(obsBody(o))
	}
	t := branches(tree.New())
	for _, c := range order {
		t.Child(branches(groups[c]))
	}
	out := indent(trimTrailing(t.String()))
	if len(shown) < len(obs) {
		out += "\n" + indent(Dim.Render(fmt.Sprintf("... %d more findings, rerun with --max 0", len(obs)-len(shown))))
	}
	return out
}

var trailingSpace = regexp.MustCompile(`(?m) +((?:\x1b\[[0-9;]*m)*)$`)

// trimTrailing drops the padding the tree adds to make every item as wide
// as its widest line.
func trimTrailing(s string) string { return trailingSpace.ReplaceAllString(s, "$1") }

func branches(t *tree.Tree) *tree.Tree {
	return t.EnumeratorStyle(Dim).IndenterStyle(Dim).
		Enumerator(func(children tree.Children, i int) string {
			if i == children.Length()-1 {
				return "└─ "
			}
			return "├─ "
		}).
		Indenter(func(children tree.Children, i int) string {
			if i == children.Length()-1 {
				return "   "
			}
			return "│  "
		})
}

var changeTag = map[snapshot.Kind]string{
	snapshot.New:     Bold.Render("+new "),
	snapshot.Changed: Bold.Render("~chg "),
	snapshot.Gone:    Dim.Render("-gone"),
}

// RenderChanges lists a diff, new and changed first.
func RenderChanges(changes []snapshot.Change, max int) string {
	if len(changes) == 0 {
		return indent(Green.Render("no changes since baseline"))
	}
	var b strings.Builder
	for i, c := range changes {
		if max > 0 && i >= max {
			b.WriteString(indent(Dim.Render(fmt.Sprintf("... %d more changes, rerun with --max 0", len(changes)-i))) + "\n")
			break
		}
		var line string
		if c.Kind == snapshot.Gone {
			line = Dim.Render(sanitize.Clean(c.Obs.Check+" "+c.Obs.Msg+"  "+c.Obs.Key, 200))
		} else {
			line = SevTag(c.Obs.Sev) + " " + fmt.Sprintf("%-9s", c.Obs.Check) + sanitize.Clean(c.Obs.Msg, 160) +
				"\n           " + Dim.Render(sanitize.Clean(c.Obs.Key, 160))
			if c.Obs.Detail != "" {
				d := sanitize.Clean(c.Obs.Detail, 220)
				if c.Obs.Sev == snapshot.Crit {
					d = Red.UnsetBold().Render(d)
				}
				line += "  " + d
			}
		}
		b.WriteString(indent(changeTag[c.Kind]+" "+line) + "\n")
		if c.Kind == snapshot.Changed && c.Old != nil && c.Old.Detail != "" && c.Old.Detail != c.Obs.Detail {
			b.WriteString("           " + Dim.Render("was: "+sanitize.Clean(c.Old.Detail, 200)) + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// Summary is the end-of-sweep table, one row per host.
func Summary(results []sweep.Result) string {
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(Dim).
		Headers("host", "crit", "warn", "status")
	styles := map[[2]int]lipgloss.Style{}
	for i, r := range results {
		if r.Err != nil {
			t.Row(r.Host.Name, "", "", "FAILED "+sanitize.Clean(r.Err.Error(), 60))
			styles[[2]int{i, 3}] = Red
			continue
		}
		crit, warn, _ := r.Snap.Counts()
		status := fmt.Sprintf("%d changes", len(r.Changes))
		if r.NewBase {
			status = "new baseline"
		}
		t.Row(r.Host.Name, strconv.Itoa(crit), strconv.Itoa(warn), status)
		styles[[2]int{i, 1}] = SevStyle(snapshot.Crit, crit)
		styles[[2]int{i, 2}] = SevStyle(snapshot.Warn, warn)
		if crit > 0 {
			styles[[2]int{i, 0}] = Red
		}
	}
	t.StyleFunc(func(row, col int) lipgloss.Style {
		base := lipgloss.NewStyle().Padding(0, 1)
		if row == table.HeaderRow {
			return base.Inherit(Dim)
		}
		if col == 1 || col == 2 {
			base = base.Align(lipgloss.Right)
		}
		if s, ok := styles[[2]int{row, col}]; ok {
			return base.Inherit(s)
		}
		return base
	})
	return indent(t.String())
}
