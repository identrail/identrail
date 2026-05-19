//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris && !windows

package repoexposure

import "os/exec"

func configureRepositoryCommand(_ *exec.Cmd) {}
