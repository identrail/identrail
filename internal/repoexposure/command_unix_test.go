//go:build aix || android || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package repoexposure

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestDefaultCommandRunnerCancelsDescendantProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	cmd := exec.CommandContext(ctx, "sh", "-c", "(sleep 30) & wait")
	configureRepositoryCommand(cmd)
	_, err := cmd.CombinedOutput()
	if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("expected command cancellation after deadline, err=%v ctx=%v", err, ctx.Err())
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("expected command tree to stop promptly, elapsed %s", elapsed)
	}
}
