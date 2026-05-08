package textutil

import "strings"

// FirstNonEmpty returns the first non-empty string exactly as provided.
func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// FirstNonEmptyTrimmed returns the first non-empty trimmed string.
func FirstNonEmptyTrimmed(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
