//go:build aix || android || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package repoexposure

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func configureRepositoryCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
			err = syscall.Kill(-pgid, syscall.SIGKILL)
			if err == nil || errors.Is(err, syscall.ESRCH) {
				return nil
			}
		}
		err := cmd.Process.Kill()
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		return err
	}
}
