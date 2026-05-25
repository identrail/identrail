package repoexposure

import "testing"

func TestRepositoryCommandName(t *testing.T) {
	t.Run("accepts git", func(t *testing.T) {
		if got := repositoryCommandName("git"); got != "git" {
			t.Fatalf("expected 'git', got %q", got)
		}
	})

	t.Run("falls back on invalid command", func(t *testing.T) {
		if got := repositoryCommandName("/usr/bin/bash"); got != defaultRepositoryCommand {
			t.Fatalf("expected fallback %q, got %q", defaultRepositoryCommand, got)
		}
	})
}
