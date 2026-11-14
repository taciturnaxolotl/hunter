// Package sanitize makes text pulled off a target safe to print and safe
// to hand to a model. Red team controls file contents, unit descriptions
// and process names, so everything from a box is treated as hostile.
package sanitize

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/charmbracelet/x/ansi"
)

// Clean escapes control characters (terminal escapes, fake newlines) so
// they show up as evidence instead of acting on the terminal, then
// truncates to width cells without splitting a character.
func Clean(s string, width int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r == '\n':
			b.WriteString(" ⏎ ")
		case unicode.IsControl(r) || r == unicode.ReplacementChar:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
		if b.Len() > 4*width {
			break
		}
	}
	return ansi.Truncate(b.String(), width, "…")
}
