package tui

import "charm.land/bubbles/v2/key"

type keyMap struct {
	Up, Down, Open, Back, Baseline, SweepNow, Quit, ForceQuit key.Binding
}

func defaultKeys() keyMap {
	return keyMap{
		Up:        key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:      key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Open:      key.NewBinding(key.WithKeys("enter", "l"), key.WithHelp("enter", "details")),
		Back:      key.NewBinding(key.WithKeys("esc", "h"), key.WithHelp("esc", "back")),
		Baseline:  key.NewBinding(key.WithKeys("b"), key.WithHelp("b", "accept as baseline")),
		SweepNow:  key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "sweep now")),
		Quit:      key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "quit")),
		ForceQuit: key.NewBinding(key.WithKeys("ctrl+c")),
	}
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Open, k.Baseline, k.SweepNow, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.ShortHelp()} }

// detailKeys is the help shown while reading one host.
type detailKeys struct{ keyMap }

func (k detailKeys) ShortHelp() []key.Binding {
	return []key.Binding{
		key.NewBinding(key.WithKeys("up", "down"), key.WithHelp("↑/↓", "scroll")),
		k.Back,
	}
}

func (k detailKeys) FullHelp() [][]key.Binding { return [][]key.Binding{k.ShortHelp()} }
