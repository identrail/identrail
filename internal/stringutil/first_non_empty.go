package stringutil

import "strings"

// FirstNonEmpty returns the first non-empty value in order.
func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// FirstNonBlankTrimmed returns the first non-blank value after trimming whitespace.
func FirstNonBlankTrimmed(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
