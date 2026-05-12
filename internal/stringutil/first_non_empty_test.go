package stringutil

import "testing"

func TestFirstNonEmpty(t *testing.T) {
	if got := FirstNonEmpty("", "first", "second"); got != "first" {
		t.Fatalf("expected first non-empty value, got %q", got)
	}
	if got := FirstNonEmpty("", ""); got != "" {
		t.Fatalf("expected empty fallback, got %q", got)
	}
}

func TestFirstNonBlankTrimmed(t *testing.T) {
	if got := FirstNonBlankTrimmed("  ", "\tvalue\n", "next"); got != "value" {
		t.Fatalf("expected first trimmed non-blank value, got %q", got)
	}
	if got := FirstNonBlankTrimmed(" ", "\t"); got != "" {
		t.Fatalf("expected empty fallback, got %q", got)
	}
}
