package report

import (
	"charm.land/lipgloss/v2"

	"github.com/taciturnaxolotl/hunter/internal/snapshot"
)

// Basic ANSI colors so the report follows the terminal's own theme.
var (
	Red    = lipgloss.NewStyle().Foreground(lipgloss.Red).Bold(true)
	Yellow = lipgloss.NewStyle().Foreground(lipgloss.Yellow).Bold(true)
	Green  = lipgloss.NewStyle().Foreground(lipgloss.Green).Bold(true)
	Dim    = lipgloss.NewStyle().Faint(true)
	Bold   = lipgloss.NewStyle().Bold(true)
)

// SevTag is the fixed-width severity label at the start of a finding.
func SevTag(s snapshot.Sev) string {
	switch s {
	case snapshot.Crit:
		return Red.Render("CRIT")
	case snapshot.Warn:
		return Yellow.Render("WARN")
	default:
		return Dim.Render("info")
	}
}

// SevStyle colors a count or label by how bad it is; zero stays plain.
func SevStyle(s snapshot.Sev, n int) lipgloss.Style {
	switch {
	case n == 0:
		return lipgloss.NewStyle()
	case s == snapshot.Crit:
		return Red
	case s == snapshot.Warn:
		return Yellow
	}
	return lipgloss.NewStyle()
}
