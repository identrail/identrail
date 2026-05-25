package repoexposure

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

const defaultCommandWaitDelay = 5 * time.Second
const defaultRepositoryCommand = "git"

func newRepositoryCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	if ctx == nil {
		ctx = context.Background()
	}
	command := repositoryCommandName(name)
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.WaitDelay = defaultCommandWaitDelay
	configureRepositoryCommand(cmd)
	return cmd
}

func repositoryCommandName(raw string) string {
	command := strings.TrimSpace(raw)
	if command == defaultRepositoryCommand {
		return command
	}
	return defaultRepositoryCommand
}
