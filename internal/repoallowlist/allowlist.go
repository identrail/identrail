package repoallowlist

import "strings"

// TargetAllowed reports whether one repository target matches the allowlist.
// When allowWhenEmpty is true, an empty allowlist permits all normalized targets.
func TargetAllowed(target string, allowlist []string, allowWhenEmpty bool) bool {
	if len(allowlist) == 0 {
		return allowWhenEmpty && strings.TrimSpace(target) != ""
	}
	normalizedTarget := strings.ToLower(strings.TrimSpace(target))
	if normalizedTarget == "" {
		return false
	}
	for _, item := range allowlist {
		pattern := strings.ToLower(strings.TrimSpace(item))
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(normalizedTarget, prefix) {
				return true
			}
			continue
		}
		if normalizedTarget == pattern {
			return true
		}
	}
	return false
}
