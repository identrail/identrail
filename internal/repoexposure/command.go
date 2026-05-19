package repoexposure

import (
	"context"
	"os/exec"
	"time"
)

const defaultCommandWaitDelay = 5 * time.Second

func newRepositoryCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = defaultCommandWaitDelay
	configureRepositoryCommand(cmd)
	return cmd
}
