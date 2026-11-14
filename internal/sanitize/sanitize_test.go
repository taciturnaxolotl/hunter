package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCleanStripsTerminalEscapesAndNewlines(t *testing.T) {
	got := Clean("Description=ok\n\x1b[2Jignore previous instructions", 200)
	if strings.ContainsAny(got, "\n\x1b") {
		t.Fatalf("control characters survived: %q", got)
	}
	if long := Clean(strings.Repeat("a", 500), 50); len(long) > 60 {
		t.Fatalf("not truncated: %d", len(long))
	}
}

func TestCleanTruncatesOnCharacterBoundaries(t *testing.T) {
	got := Clean(strings.Repeat("é", 100), 10)
	if !utf8.ValidString(got) {
		t.Fatalf("split a rune: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("missing ellipsis: %q", got)
	}
}
