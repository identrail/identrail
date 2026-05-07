package textutil

import "testing"

func TestFirstNonEmpty(t *testing.T) {
	t.Run("returns empty when no values match", func(t *testing.T) {
		if got := FirstNonEmpty("", "", ""); got != "" {
			t.Fatalf("expected empty result, got %q", got)
		}
	})

	t.Run("returns first exact non-empty value", func(t *testing.T) {
		if got := FirstNonEmpty("", " value ", "fallback"); got != " value " {
			t.Fatalf("expected exact first non-empty value, got %q", got)
		}
	})
}

func TestFirstNonEmptyTrimmed(t *testing.T) {
	t.Run("returns empty when all values are blank", func(t *testing.T) {
		if got := FirstNonEmptyTrimmed("", "   ", "\n\t"); got != "" {
			t.Fatalf("expected empty result, got %q", got)
		}
	})

	t.Run("returns first trimmed non-empty value", func(t *testing.T) {
		if got := FirstNonEmptyTrimmed("   ", " value ", "fallback"); got != "value" {
			t.Fatalf("expected trimmed first non-empty value, got %q", got)
		}
	})
}
