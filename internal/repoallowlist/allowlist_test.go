package repoallowlist

import "testing"

func TestTargetAllowedEmptyAllowlistPolicy(t *testing.T) {
	if TargetAllowed("owner/repo", nil, false) {
		t.Fatal("expected empty allowlist to deny target when allowWhenEmpty is false")
	}
	if !TargetAllowed("owner/repo", nil, true) {
		t.Fatal("expected empty allowlist to allow target when allowWhenEmpty is true")
	}
	if TargetAllowed("   ", nil, true) {
		t.Fatal("expected blank targets to remain denied")
	}
}

func TestTargetAllowedWildcardAndExact(t *testing.T) {
	allowlist := []string{"trusted/*", "owner/repo"}
	if !TargetAllowed("trusted/project-a", allowlist, false) {
		t.Fatal("expected wildcard allowlist to match target")
	}
	if !TargetAllowed("owner/repo", allowlist, false) {
		t.Fatal("expected exact allowlist to match target")
	}
	if TargetAllowed("other/repo", allowlist, false) {
		t.Fatal("expected non-matching target to be denied")
	}
}
